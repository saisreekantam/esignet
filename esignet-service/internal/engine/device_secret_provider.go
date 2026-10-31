/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"

	"github.com/mosip/esignet/internal/clientmgmt"
	"github.com/mosip/esignet/internal/config"
	"github.com/mosip/esignet/internal/engine/shared"
	"github.com/mosip/esignet/internal/keymanager"
	"github.com/mosip/esignet/internal/keymanager/cryptomanager"
	"github.com/mosip/esignet/internal/keymanager/signature"
	applog "github.com/mosip/esignet/internal/log"
)

const (
	// NativeSSOAllowedClientsKey is the additional_config key listing the client ids that may sign in
	// through Native SSO with a device secret minted for this client. Only clients registered under
	// the same relying party (vendor) are honored.
	NativeSSOAllowedClientsKey = "native_sso_allowed_client_ids"

	// deviceSecretTokenUse marks a JWS as a device secret so no other esignet-signed JWT can be
	// redeemed in its place.
	deviceSecretTokenUse = "device_secret"

	nativeSSOSessionNamespace    providers.RuntimeStoreNamespace = "native_sso:session"
	nativeSSORedemptionNamespace providers.RuntimeStoreNamespace = "native_sso:redemption"
)

// deviceSecretPayload is the claim set of a device secret. It is signed with esignet's EC sign key
// and then encrypted with the Native SSO Component Encryption Key, so it is opaque to clients.
type deviceSecretPayload struct {
	Issuer           string          `json:"iss"`
	Subject          string          `json:"sub"`
	SessionID        string          `json:"sid"`
	AuthID           string          `json:"auth_id"`
	ClientID         string          `json:"client_id"`
	Scope            string          `json:"scope"`
	ACR              string          `json:"acr,omitempty"`
	Claims           map[string]any  `json:"claims,omitempty"`
	Cnf              deviceSecretCnf `json:"cnf"`
	AttributeCacheID string          `json:"aci,omitempty"`
	AuthTime         int64           `json:"auth_time,omitempty"`
	TokenUse         string          `json:"token_use"`
	JTI              string          `json:"jti"`
	IssuedAt         int64           `json:"iat"`
	Expiry           int64           `json:"exp"`
}

type deviceSecretCnf struct {
	Jkt string `json:"jkt"`
}

// nativeSSOSession is the server-side state of an SSO session. A device secret is only redeemable
// while its session exists, so deleting the session ends SSO for every app of the vendor.
type nativeSSOSession struct {
	Subject    string   `json:"sub"`
	ClientID   string   `json:"client_id"`
	JTI        string   `json:"jti"`
	ExpiresAt  int64    `json:"exp"`
	RedeemedBy []string `json:"redeemed_by,omitempty"`
}

type jwsService interface {
	JWSSign(ctx context.Context, req signature.JWSSignRequest) (signature.JWSSignResponse, error)
	JWSVerify(ctx context.Context, req signature.JWSVerifyRequest) (signature.JWSVerifyResponse, error)
}

type jweService interface {
	JWTEncrypt(ctx context.Context, req cryptomanager.JWTEncryptRequest) (cryptomanager.JWTCipherResponse, error)
	JWTDecrypt(ctx context.Context, req cryptomanager.JWTDecryptRequest) (cryptomanager.JWTCipherResponse, error)
}

type activeClientLookup interface {
	GetActiveClient(ctx context.Context, clientID string) (clientmgmt.ClientResponse, error)
}

type deviceSecretProvider struct {
	cfg     *config.AppConfig
	signer  jwsService
	cipher  jweService
	clients activeClientLookup
	store   providers.RuntimeStoreProvider
	logger  *applog.Logger
	now     func() time.Time
}

// NewDeviceSecretProvider returns the providers.DeviceSecretProvider that enables OpenID Connect
// Native SSO for Mobile Apps 1.0, or nil when Native SSO is disabled.
func NewDeviceSecretProvider(cfg *config.AppConfig, sigSvc *signature.Service, cryptoSvc *cryptomanager.Service,
	clientSvc *clientmgmt.Service, store providers.RuntimeStoreProvider) providers.DeviceSecretProvider {
	if !cfg.NativeSSO.Enabled {
		return nil
	}
	return newDeviceSecretProvider(cfg, sigSvc, cryptoSvc, clientSvc, store)
}

func newDeviceSecretProvider(cfg *config.AppConfig, signer jwsService, cipher jweService,
	clients activeClientLookup, store providers.RuntimeStoreProvider) *deviceSecretProvider {
	return &deviceSecretProvider{
		cfg:     cfg,
		signer:  signer,
		cipher:  cipher,
		clients: clients,
		store:   store,
		logger:  applog.GetLogger().Named("deviceSecretProvider"),
		now:     time.Now,
	}
}

// GenerateDeviceSecret mints a signed-then-encrypted device secret bound to the DPoP key in req and
// opens the SSO session it represents.
func (p *deviceSecretProvider) GenerateDeviceSecret(ctx context.Context, req *providers.DeviceSecretRequest) (
	*providers.DeviceSecret, *common.ServiceError) {
	if req == nil || req.Subject == "" || req.AuthID == "" || req.ClientID == "" || req.CnfJkt == "" {
		return nil, nativeSSOError("invalid_device_secret_request", "The device secret request is incomplete")
	}

	now := p.now().UTC()
	expiresAt := now.Add(time.Duration(p.cfg.NativeSSO.DeviceSecretValiditySecs) * time.Second)
	payload := deviceSecretPayload{
		Issuer:           p.cfg.Issuer,
		Subject:          req.Subject,
		SessionID:        req.AuthID,
		AuthID:           req.AuthID,
		ClientID:         req.ClientID,
		Scope:            strings.Join(req.Scopes, " "),
		ACR:              req.ACR,
		Claims:           req.Claims,
		Cnf:              deviceSecretCnf{Jkt: req.CnfJkt},
		AttributeCacheID: req.AttributeCacheID,
		AuthTime:         req.AuthTime,
		TokenUse:         deviceSecretTokenUse,
		JTI:              uuid.NewString(),
		IssuedAt:         now.Unix(),
		Expiry:           expiresAt.Unix(),
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		p.logger.Error(ctx, "Failed to encode device secret", applog.Error(err))
		return nil, shared.InternalServerError
	}
	signed, err := p.signer.JWSSign(ctx, signature.JWSSignRequest{
		ApplicationID: config.OIDCServiceAppID,
		ReferenceID:   keymanager.RefIDECSECP256R1Sign,
		DataToSign:    base64.RawURLEncoding.EncodeToString(raw),
		IncludeKeyID:  true,
	})
	if err != nil {
		p.logger.Error(ctx, "Failed to sign device secret", applog.Error(err))
		return nil, shared.InternalServerError
	}
	encrypted, err := p.cipher.JWTEncrypt(ctx, cryptomanager.JWTEncryptRequest{
		ApplicationID: config.OIDCServiceAppID,
		ReferenceID:   p.cfg.NativeSSO.EncryptionReferenceID,
		Data:          signed.JWTSignedData,
	})
	if err != nil {
		p.logger.Error(ctx, "Failed to encrypt device secret", applog.Error(err))
		return nil, shared.InternalServerError
	}

	session, err := json.Marshal(nativeSSOSession{
		Subject:   req.Subject,
		ClientID:  req.ClientID,
		JTI:       payload.JTI,
		ExpiresAt: payload.Expiry,
	})
	if err != nil {
		return nil, shared.InternalServerError
	}
	if err := p.store.Put(ctx, nativeSSOSessionNamespace, payload.SessionID, session,
		int64(p.cfg.NativeSSO.DeviceSecretValiditySecs)); err != nil {
		p.logger.Error(ctx, "Failed to open the Native SSO session", applog.Error(err))
		return nil, shared.InternalServerError
	}

	p.logger.Info(ctx, "Native SSO device secret issued", applog.String("clientId", req.ClientID),
		applog.String("sid", payload.SessionID))
	return &providers.DeviceSecret{Value: encrypted.Data, ExpiresAt: expiresAt}, nil
}

// ValidateDeviceSecret decrypts and verifies a device secret presented by clientID and checks that
// its SSO session is still open and that clientID may redeem it.
func (p *deviceSecretProvider) ValidateDeviceSecret(ctx context.Context, clientID, deviceSecret string) (
	*providers.DeviceSecretClaims, *common.ServiceError) {
	payload, svcErr := p.decode(ctx, deviceSecret)
	if svcErr != nil {
		return nil, svcErr
	}

	session, svcErr := p.session(ctx, payload.SessionID)
	if svcErr != nil {
		return nil, svcErr
	}
	if session == nil || session.JTI != payload.JTI {
		return nil, nativeSSOError("native_sso_session_ended", "The SSO session has ended")
	}

	if svcErr := p.authorizeRedemption(ctx, payload.ClientID, clientID); svcErr != nil {
		return nil, svcErr
	}

	return &providers.DeviceSecretClaims{
		ID:               payload.JTI,
		Issuer:           payload.Issuer,
		Subject:          payload.Subject,
		SessionID:        payload.SessionID,
		ClientID:         payload.ClientID,
		Scopes:           strings.Fields(payload.Scope),
		ACR:              payload.ACR,
		Claims:           payload.Claims,
		CnfJkt:           payload.Cnf.Jkt,
		AttributeCacheID: payload.AttributeCacheID,
		AuthTime:         payload.AuthTime,
		ExpiresAt:        time.Unix(payload.Expiry, 0).UTC(),
	}, nil
}

// MarkDeviceSecretUsed records that clientID redeemed the device secret. The redemption is claimed
// atomically on jti|client, so of several concurrent replays only one wins. The claim lasts for the
// access token's lifetime under once_per_token_lifetime (one live token per app and session, and a
// silent re-sign-in once it expires) and for the device secret's lifetime under once_per_client.
func (p *deviceSecretProvider) MarkDeviceSecretUsed(ctx context.Context, claims *providers.DeviceSecretClaims,
	clientID string) *common.ServiceError {
	if claims == nil {
		return nativeSSOError("invalid_device_secret", "Invalid device secret")
	}
	ttl := int64(time.Until(claims.ExpiresAt).Seconds())
	if ttl <= 0 {
		return nativeSSOError("device_secret_expired", "The device secret has expired")
	}

	if lockTTL, single := p.redemptionLockTTL(ttl); single {
		stored, err := p.store.PutIfNotExists(ctx, nativeSSORedemptionNamespace, claims.ID+"|"+clientID,
			[]byte(p.now().UTC().Format(time.RFC3339)), lockTTL)
		if err != nil {
			p.logger.Error(ctx, "Failed to record device secret redemption", applog.Error(err))
			return shared.InternalServerError
		}
		if !stored {
			p.logger.Warn(ctx, "Device secret replayed", applog.String("clientId", clientID),
				applog.String("sid", claims.SessionID))
			return nativeSSOError("device_secret_already_redeemed",
				"The device secret has already been redeemed by this client")
		}
	}

	// Track which apps joined the session; best effort, it does not gate the redemption.
	if session, svcErr := p.session(ctx, claims.SessionID); svcErr == nil && session != nil &&
		!slices.Contains(session.RedeemedBy, clientID) {
		session.RedeemedBy = append(session.RedeemedBy, clientID)
		if raw, err := json.Marshal(session); err == nil {
			if err := p.store.Update(ctx, nativeSSOSessionNamespace, claims.SessionID, raw); err != nil {
				p.logger.Warn(ctx, "Failed to record the Native SSO session member", applog.Error(err))
			}
		}
	}

	p.logger.Info(ctx, "Native SSO device secret redeemed", applog.String("clientId", clientID),
		applog.String("originalClientId", claims.ClientID), applog.String("sid", claims.SessionID))
	return nil
}

// redemptionLockTTL returns how long a redemption by one client blocks the next one, and false
// when the policy does not limit redemptions. secretTTL is the device secret's remaining lifetime.
func (p *deviceSecretProvider) redemptionLockTTL(secretTTL int64) (int64, bool) {
	switch p.cfg.NativeSSO.RedemptionPolicy {
	case config.NativeSSORedeemReusable:
		return 0, false
	case config.NativeSSORedeemOncePerClient:
		return secretTTL, true
	default:
		tokenTTL := p.cfg.JWT.ValidityPeriod
		if tokenTTL <= 0 || tokenTTL > secretTTL {
			tokenTTL = secretTTL
		}
		return tokenTTL, true
	}
}

// IsSessionActive reports whether the SSO session sid is still open.
func (p *deviceSecretProvider) IsSessionActive(ctx context.Context, sid string) (bool, *common.ServiceError) {
	session, svcErr := p.session(ctx, sid)
	if svcErr != nil {
		return false, svcErr
	}
	return session != nil, nil
}

// EndSession ends the SSO session the device secret belongs to, so no app can redeem it again. It
// returns the apps that had joined the session.
func (p *deviceSecretProvider) EndSession(ctx context.Context, deviceSecret string) ([]string, *common.ServiceError) {
	payload, svcErr := p.decode(ctx, deviceSecret)
	if svcErr != nil {
		return nil, svcErr
	}
	session, svcErr := p.session(ctx, payload.SessionID)
	if svcErr != nil {
		return nil, svcErr
	}
	if session == nil || session.JTI != payload.JTI {
		return nil, nativeSSOError("native_sso_session_ended", "The SSO session has ended")
	}
	if err := p.store.Delete(ctx, nativeSSOSessionNamespace, payload.SessionID); err != nil {
		p.logger.Error(ctx, "Failed to end the Native SSO session", applog.Error(err))
		return nil, shared.InternalServerError
	}
	p.logger.Info(ctx, "Native SSO session ended", applog.String("sid", payload.SessionID),
		applog.Int("memberCount", len(session.RedeemedBy)))
	return append([]string{payload.ClientID}, session.RedeemedBy...), nil
}

// decode decrypts, verifies and parses a device secret, rejecting anything that is not an
// unexpired device secret issued by this server.
func (p *deviceSecretProvider) decode(ctx context.Context, deviceSecret string) (*deviceSecretPayload,
	*common.ServiceError) {
	invalid := nativeSSOError("invalid_device_secret", "Invalid device secret")
	if strings.Count(deviceSecret, ".") != 4 {
		return nil, invalid
	}

	decrypted, err := p.cipher.JWTDecrypt(ctx, cryptomanager.JWTDecryptRequest{
		ApplicationID: config.OIDCServiceAppID,
		ReferenceID:   p.cfg.NativeSSO.EncryptionReferenceID,
		EncData:       deviceSecret,
	})
	if err != nil {
		p.logger.Debug(ctx, "Device secret decryption failed", applog.Error(err))
		return nil, invalid
	}
	jws, err := base64.RawURLEncoding.DecodeString(decrypted.Data)
	if err != nil {
		return nil, invalid
	}

	verified, err := p.signer.JWSVerify(ctx, signature.JWSVerifyRequest{
		JWTSignatureData: string(jws),
		ApplicationID:    config.OIDCServiceAppID,
		ReferenceID:      keymanager.RefIDECSECP256R1Sign,
	})
	if err != nil || !verified.SignatureValid {
		p.logger.Debug(ctx, "Device secret signature verification failed", applog.Error(err))
		return nil, invalid
	}

	parts := strings.Split(string(jws), ".")
	rawPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, invalid
	}
	var payload deviceSecretPayload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return nil, invalid
	}
	if payload.TokenUse != deviceSecretTokenUse || payload.Issuer != p.cfg.Issuer || payload.JTI == "" ||
		payload.SessionID == "" || payload.Subject == "" || payload.ClientID == "" || payload.Cnf.Jkt == "" {
		return nil, invalid
	}
	if p.now().Unix() >= payload.Expiry {
		return nil, nativeSSOError("device_secret_expired", "The device secret has expired")
	}
	return &payload, nil
}

func (p *deviceSecretProvider) session(ctx context.Context, sid string) (*nativeSSOSession, *common.ServiceError) {
	raw, err := p.store.Get(ctx, nativeSSOSessionNamespace, sid)
	if err != nil {
		p.logger.Error(ctx, "Failed to read the Native SSO session", applog.Error(err))
		return nil, shared.InternalServerError
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var session nativeSSOSession
	if err := json.Unmarshal(raw, &session); err != nil {
		p.logger.Error(ctx, "Failed to decode the Native SSO session", applog.Error(err))
		return nil, shared.InternalServerError
	}
	return &session, nil
}

// authorizeRedemption allows the original client to redeem its own device secret, and another
// client only when it is registered under the same relying party (vendor) and the original client
// lists it in its Native SSO allow-list.
func (p *deviceSecretProvider) authorizeRedemption(ctx context.Context, originalClientID, clientID string) *common.ServiceError {
	if clientID == originalClientID {
		return nil
	}
	denied := nativeSSOError("native_sso_client_not_allowed",
		"The client is not allowed to sign in with this device secret")

	original, err := p.clients.GetActiveClient(ctx, originalClientID)
	if err != nil {
		return p.clientLookupError(ctx, err, denied)
	}
	requesting, err := p.clients.GetActiveClient(ctx, clientID)
	if err != nil {
		return p.clientLookupError(ctx, err, denied)
	}
	if original.RpID == "" || original.RpID != requesting.RpID {
		p.logger.Warn(ctx, "Native SSO denied across relying parties", applog.String("clientId", clientID),
			applog.String("originalClientId", originalClientID))
		return denied
	}
	if !slices.Contains(stringSliceConfig(original.AdditionalConfig, NativeSSOAllowedClientsKey), clientID) {
		p.logger.Warn(ctx, "Native SSO denied, client not in allow-list", applog.String("clientId", clientID),
			applog.String("originalClientId", originalClientID))
		return denied
	}
	return nil
}

func (p *deviceSecretProvider) clientLookupError(ctx context.Context, err error,
	denied *common.ServiceError) *common.ServiceError {
	if errors.Is(err, clientmgmt.ErrClientNotFound) {
		return denied
	}
	p.logger.Error(ctx, "Client lookup failed", applog.Error(err))
	return shared.InternalServerError
}

func stringSliceConfig(additionalConfig map[string]any, key string) []string {
	v, ok := additionalConfig[key].([]any)
	if !ok {
		return nil
	}
	values := make([]string, 0, len(v))
	for _, item := range v {
		if s, ok := item.(string); ok {
			values = append(values, s)
		}
	}
	return values
}

func nativeSSOError(code, description string) *common.ServiceError {
	return &common.ServiceError{
		Code:             code,
		Type:             common.ClientErrorType,
		Error:            common.I18nMessage{Key: code, DefaultValue: description},
		ErrorDescription: common.I18nMessage{Key: code + "_description", DefaultValue: description},
	}
}
