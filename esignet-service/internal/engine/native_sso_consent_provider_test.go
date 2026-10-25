/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package engine

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"

	"github.com/mosip/esignet/internal/config"
	"github.com/mosip/esignet/internal/consentmgmt"
)

type reusedConsent struct {
	record     *consentmgmt.ConsentRecord
	reusedFrom string
}

type fakeConsentStore struct {
	records  map[string]*consentmgmt.ConsentRecord
	fetchErr error
	history  []reusedConsent
}

func (f *fakeConsentStore) FetchRecord(_ context.Context, clientID, userID string) (*consentmgmt.ConsentRecord, error) {
	if f.fetchErr != nil {
		return nil, f.fetchErr
	}
	return f.records[clientID+"|"+userID], nil
}

func (f *fakeConsentStore) AppendReusedConsentHistory(_ context.Context, c *consentmgmt.ConsentRecord,
	reusedFrom string) error {
	f.history = append(f.history, reusedConsent{record: c, reusedFrom: reusedFrom})
	return nil
}

type NativeSSOConsentProviderTestSuite struct {
	suite.Suite
	store    *fakeConsentStore
	provider *nativeSSOConsentProvider
}

func TestNativeSSOConsentProviderTestSuite(t *testing.T) {
	suite.Run(t, new(NativeSSOConsentProviderTestSuite))
}

func (ts *NativeSSOConsentProviderTestSuite) SetupTest() {
	cfg := &config.AppConfig{
		ScopeClaims: map[string][]string{
			"openid":  nil,
			"profile": {"name", "gender", "birthdate", "picture"},
			"email":   {"email", "email_verified"},
			"phone":   {"phone_number"},
		},
		ResourceServers: []config.ResourceServerConfig{{
			ID: "vci", Identifier: "https://esignet.example.com/vci", Scopes: map[string]string{"vc:issue": "Issue a VC"},
		}},
	}
	ts.store = &fakeConsentStore{records: map[string]*consentmgmt.ConsentRecord{
		"super|psut-1": {
			ClientID: "super", UserID: "psut-1",
			Claims:          map[string]any{"userinfo": map[string]any{"name": nil}},
			AcceptedClaims:  []string{"name", "gender", "phone_number"},
			PermittedScopes: []string{"vc:issue"},
		},
	}}
	clients := fakeClients{"child": {ClientID: "child", Claims: []string{"name", "email", "phone_number"}}}
	ts.provider = newNativeSSOConsentProvider(ts.store, clients, cfg)
}

func (ts *NativeSSOConsentProviderTestSuite) request(scopes ...string) *providers.NativeSSOConsentRequest {
	return &providers.NativeSSOConsentRequest{
		Subject: "psut-1", ClientID: "child", OriginalClientID: "super", RequestedScopes: scopes, SessionID: "sid-1",
	}
}

func (ts *NativeSSOConsentProviderTestSuite) TestResolve() {
	cases := []struct {
		name    string
		scopes  []string
		missing []string
	}{
		{name: "standard scopes with accepted claims", scopes: []string{"openid", "profile", "phone"}},
		{name: "permitted authorization scope", scopes: []string{"openid", "vc:issue"}},
		{name: "declined claim", scopes: []string{"openid", "profile", "email"}, missing: []string{"email"}},
		{name: "unknown scope", scopes: []string{"openid", "address"}, missing: []string{"address"}},
	}
	for _, tc := range cases {
		ts.Run(tc.name, func() {
			result, svcErr := ts.provider.ResolveNativeSSOConsent(context.Background(), ts.request(tc.scopes...))
			ts.Require().Nil(svcErr)
			ts.Equal(len(tc.missing) == 0, result.Covered)
			ts.Equal(tc.missing, result.MissingScopes)
		})
	}
	ts.Empty(ts.store.history, "resolving consent must not write audit records")
}

func (ts *NativeSSOConsentProviderTestSuite) TestResolveReturnsOnlyReleasableClaims() {
	result, svcErr := ts.provider.ResolveNativeSSOConsent(context.Background(), ts.request("openid", "profile"))
	ts.Require().Nil(svcErr)
	ts.True(result.Covered)
	// profile releases name, gender, birthdate and picture; the child is registered only for name,
	// and the user did not accept birthdate or picture.
	ts.Equal([]string{"name"}, result.ReleasableClaims)
}

func (ts *NativeSSOConsentProviderTestSuite) TestResolveWithoutUsableOriginalConsent() {
	req := ts.request("openid", "profile")
	req.Subject = "psut-without-consent"
	result, svcErr := ts.provider.ResolveNativeSSOConsent(context.Background(), req)
	ts.Require().Nil(svcErr)
	ts.False(result.Covered)
	ts.Equal([]string{"profile"}, result.MissingScopes)

	ts.store.records["super|psut-1"].ExpiresAt = sql.NullTime{Time: time.Now().Add(-time.Hour), Valid: true}
	result, svcErr = ts.provider.ResolveNativeSSOConsent(context.Background(), ts.request("openid", "profile"))
	ts.Require().Nil(svcErr)
	ts.False(result.Covered)
}

func (ts *NativeSSOConsentProviderTestSuite) TestResolveSameClientIsAlwaysCovered() {
	req := ts.request("openid", "email")
	req.ClientID = "super"
	result, svcErr := ts.provider.ResolveNativeSSOConsent(context.Background(), req)
	ts.Require().Nil(svcErr)
	ts.True(result.Covered)
}

func (ts *NativeSSOConsentProviderTestSuite) TestResolveFailsClosedOnStoreErrors() {
	ts.store.fetchErr = errors.New("db down")
	_, svcErr := ts.provider.ResolveNativeSSOConsent(context.Background(), ts.request("openid", "profile"))
	ts.Require().NotNil(svcErr)
	ts.Equal(common.ServerErrorType, svcErr.Type)
}

func (ts *NativeSSOConsentProviderTestSuite) TestRecordAuditsTheReusedConsent() {
	ts.Require().Nil(ts.provider.RecordNativeSSOConsent(context.Background(),
		ts.request("openid", "profile", "phone", "vc:issue")))

	ts.Require().Len(ts.store.history, 1)
	entry := ts.store.history[0]
	ts.Equal("super", entry.reusedFrom)
	ts.Equal("child", entry.record.ClientID)
	ts.Equal("psut-1", entry.record.UserID)
	ts.Equal([]string{"name", "phone_number"}, entry.record.AcceptedClaims,
		"only claims both accepted by the user and registered for the child are recorded")
	ts.Equal([]string{"vc:issue"}, entry.record.PermittedScopes)
}

func (ts *NativeSSOConsentProviderTestSuite) TestRecordRefusesUncoveredRequests() {
	svcErr := ts.provider.RecordNativeSSOConsent(context.Background(), ts.request("openid", "email"))
	ts.Require().NotNil(svcErr)
	ts.Empty(ts.store.history)
}
