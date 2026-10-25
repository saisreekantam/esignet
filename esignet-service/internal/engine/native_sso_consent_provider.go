/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package engine

import (
	"context"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"

	"github.com/mosip/esignet/internal/clientmgmt"
	"github.com/mosip/esignet/internal/config"
	"github.com/mosip/esignet/internal/consentmgmt"
	"github.com/mosip/esignet/internal/engine/shared"
	applog "github.com/mosip/esignet/internal/log"
)

type consentStore interface {
	FetchRecord(ctx context.Context, clientID, userID string) (*consentmgmt.ConsentRecord, error)
	AppendReusedConsentHistory(ctx context.Context, c *consentmgmt.ConsentRecord, reusedFromClientID string) error
}

type nativeSSOConsentProvider struct {
	consents consentStore
	clients  activeClientLookup
	config   *config.AppConfig
	logger   *applog.Logger
	now      func() time.Time
}

// NewNativeSSOConsentProvider returns the providers.NativeSSOConsentProvider that lets an app
// signing in through Native SSO reuse the consent the user gave to the app that minted the device
// secret, or nil when Native SSO is disabled.
func NewNativeSSOConsentProvider(consentSvc *consentmgmt.Service, clientSvc *clientmgmt.Service,
	cfg *config.AppConfig) providers.NativeSSOConsentProvider {
	if !cfg.NativeSSO.Enabled {
		return nil
	}
	return newNativeSSOConsentProvider(consentSvc, clientSvc, cfg)
}

func newNativeSSOConsentProvider(consents consentStore, clients activeClientLookup,
	cfg *config.AppConfig) *nativeSSOConsentProvider {
	return &nativeSSOConsentProvider{
		consents: consents,
		clients:  clients,
		config:   cfg,
		logger:   applog.GetLogger().Named("nativeSSOConsentProvider"),
		now:      time.Now,
	}
}

// ResolveNativeSSOConsent reports, without side effects, whether the consent the user gave to the
// original client covers every requested scope for the requesting client. A standard scope is
// covered when the user accepted at least one of the claims it releases to the requesting client;
// an authorization scope is covered when the user permitted it. The releasable claims are the
// claims the requesting client may then be served.
func (p *nativeSSOConsentProvider) ResolveNativeSSOConsent(ctx context.Context,
	req *providers.NativeSSOConsentRequest) (*providers.NativeSSOConsentResult, *common.ServiceError) {
	if req.ClientID == req.OriginalClientID {
		return &providers.NativeSSOConsentResult{Covered: true}, nil
	}
	eval, svcErr := p.evaluate(ctx, req)
	if svcErr != nil {
		return nil, svcErr
	}
	if len(eval.missing) > 0 {
		p.logger.Info(ctx, "Native SSO consent not covered by the original consent",
			applog.String("clientId", req.ClientID), applog.String("originalClientId", req.OriginalClientID))
		return &providers.NativeSSOConsentResult{MissingScopes: eval.missing}, nil
	}
	return &providers.NativeSSOConsentResult{Covered: true, ReleasableClaims: eval.acceptedClaims}, nil
}

// RecordNativeSSOConsent appends the reused consent to consent_history, so the audit trail shows
// which consent the requesting client relied on and which client it was given to. consent_detail
// is not touched: the user made no new consent decision.
func (p *nativeSSOConsentProvider) RecordNativeSSOConsent(ctx context.Context,
	req *providers.NativeSSOConsentRequest) *common.ServiceError {
	eval, svcErr := p.evaluate(ctx, req)
	if svcErr != nil {
		return svcErr
	}
	if len(eval.missing) > 0 {
		return shared.InternalServerError
	}
	reused := &consentmgmt.ConsentRecord{
		ID:                  uuid.NewString(),
		ClientID:            req.ClientID,
		UserID:              req.Subject,
		Claims:              eval.record.Claims,
		AuthorizationScopes: eval.permittedScopes,
		AcceptedClaims:      eval.acceptedClaims,
		PermittedScopes:     eval.permittedScopes,
		CreatedAt:           p.now().UTC(),
		ExpiresAt:           eval.record.ExpiresAt,
	}
	if err := p.consents.AppendReusedConsentHistory(ctx, reused, req.OriginalClientID); err != nil {
		p.logger.Error(ctx, "Failed to record the reused consent", applog.Error(err))
		return shared.InternalServerError
	}
	return nil
}

// consentEvaluation is the outcome of matching a Native SSO request against the original consent.
type consentEvaluation struct {
	record          *consentmgmt.ConsentRecord
	missing         []string
	permittedScopes []string
	acceptedClaims  []string
}

func (p *nativeSSOConsentProvider) evaluate(ctx context.Context,
	req *providers.NativeSSOConsentRequest) (*consentEvaluation, *common.ServiceError) {
	record, err := p.consents.FetchRecord(ctx, req.OriginalClientID, req.Subject)
	if err != nil {
		p.logger.Error(ctx, "Failed to read the original consent", applog.Error(err))
		return nil, shared.InternalServerError
	}
	if record == nil || record.IsExpired(p.now().UTC()) {
		return &consentEvaluation{missing: withoutOpenID(req.RequestedScopes)}, nil
	}

	client, err := p.clients.GetActiveClient(ctx, req.ClientID)
	if err != nil {
		p.logger.Error(ctx, "Failed to read the requesting client", applog.Error(err))
		return nil, shared.InternalServerError
	}

	eval := &consentEvaluation{record: record}
	for _, scope := range withoutOpenID(req.RequestedScopes) {
		if p.config.IsAuthorizationScope(scope) {
			if !slices.Contains(record.PermittedScopes, scope) {
				eval.missing = append(eval.missing, scope)
				continue
			}
			eval.permittedScopes = append(eval.permittedScopes, scope)
			continue
		}

		var covered []string
		for _, claim := range p.config.ScopeClaims[scope] {
			if slices.Contains(client.Claims, claim) && slices.Contains(record.AcceptedClaims, claim) {
				covered = append(covered, claim)
			}
		}
		if len(covered) == 0 {
			eval.missing = append(eval.missing, scope)
			continue
		}
		for _, claim := range covered {
			if !slices.Contains(eval.acceptedClaims, claim) {
				eval.acceptedClaims = append(eval.acceptedClaims, claim)
			}
		}
	}
	return eval, nil
}

func withoutOpenID(scopes []string) []string {
	return slices.DeleteFunc(slices.Clone(scopes), func(s string) bool { return s == "openid" })
}
