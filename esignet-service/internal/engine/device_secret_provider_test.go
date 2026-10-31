/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package engine

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"

	"github.com/mosip/esignet/internal/clientmgmt"
	"github.com/mosip/esignet/internal/config"
	"github.com/mosip/esignet/internal/engine/runtimestores/inmemory"
	"github.com/mosip/esignet/internal/keymanager/cryptomanager"
	"github.com/mosip/esignet/internal/keymanager/signature"
)

// fakeJWS "signs" by appending a fixed signature segment, so tampering is detectable.
type fakeJWS struct{ signErr error }

func (f *fakeJWS) JWSSign(_ context.Context, req signature.JWSSignRequest) (signature.JWSSignResponse, error) {
	if f.signErr != nil {
		return signature.JWSSignResponse{}, f.signErr
	}
	return signature.JWSSignResponse{JWTSignedData: "eyJhbGciOiJFUzI1NiJ9." + req.DataToSign + ".sig"}, nil
}

func (f *fakeJWS) JWSVerify(_ context.Context, req signature.JWSVerifyRequest) (signature.JWSVerifyResponse, error) {
	return signature.JWSVerifyResponse{SignatureValid: strings.HasSuffix(req.JWTSignatureData, ".sig")}, nil
}

// fakeJWE wraps its input in a 5-part compact form and refuses anything it did not produce.
type fakeJWE struct{}

func (fakeJWE) JWTEncrypt(_ context.Context, req cryptomanager.JWTEncryptRequest) (cryptomanager.JWTCipherResponse, error) {
	return cryptomanager.JWTCipherResponse{
		Data: "hdr.key.iv." + base64.RawURLEncoding.EncodeToString([]byte(req.Data)) + ".tag",
	}, nil
}

func (fakeJWE) JWTDecrypt(_ context.Context, req cryptomanager.JWTDecryptRequest) (cryptomanager.JWTCipherResponse, error) {
	parts := strings.Split(req.EncData, ".")
	if len(parts) != 5 || parts[0] != "hdr" || parts[4] != "tag" {
		return cryptomanager.JWTCipherResponse{}, errors.New("decryption failed")
	}
	plain, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return cryptomanager.JWTCipherResponse{}, err
	}
	return cryptomanager.JWTCipherResponse{Data: base64.RawURLEncoding.EncodeToString(plain)}, nil
}

type fakeClients map[string]clientmgmt.ClientResponse

func (f fakeClients) GetActiveClient(_ context.Context, clientID string) (clientmgmt.ClientResponse, error) {
	if clientID == "broken" {
		return clientmgmt.ClientResponse{}, errors.New("db down")
	}
	c, ok := f[clientID]
	if !ok {
		return clientmgmt.ClientResponse{}, clientmgmt.ErrClientNotFound
	}
	return c, nil
}

// recordingStore remembers the TTL of every PutIfNotExists so tests can check how long a
// redemption blocks the next one.
type recordingStore struct {
	providers.RuntimeStoreProvider
	ttls map[string]int64
}

func (r *recordingStore) PutIfNotExists(ctx context.Context, ns providers.RuntimeStoreNamespace, key string,
	value []byte, ttl int64) (bool, error) {
	r.ttls[key] = ttl
	return r.RuntimeStoreProvider.PutIfNotExists(ctx, ns, key, value, ttl)
}

type DeviceSecretProviderTestSuite struct {
	suite.Suite
	cfg      *config.AppConfig
	signer   *fakeJWS
	store    *recordingStore
	provider *deviceSecretProvider
	now      time.Time
}

func TestDeviceSecretProviderTestSuite(t *testing.T) {
	suite.Run(t, new(DeviceSecretProviderTestSuite))
}

func (ts *DeviceSecretProviderTestSuite) SetupTest() {
	ts.cfg = &config.AppConfig{
		Issuer: "https://esignet.example.com",
		NativeSSO: config.NativeSSOConfig{
			Enabled: true, DeviceSecretValiditySecs: 3600, EncryptionReferenceID: "NATIVE_SSO",
			RedemptionPolicy: config.NativeSSORedeemOncePerClient,
		},
	}
	ts.cfg.JWT.ValidityPeriod = 120
	clients := fakeClients{
		"super": {ClientID: "super", RpID: "acme", AdditionalConfig: map[string]any{
			NativeSSOAllowedClientsKey: []any{"child", "foreign"},
		}},
		"child":    {ClientID: "child", RpID: "acme"},
		"unlisted": {ClientID: "unlisted", RpID: "acme"},
		"foreign":  {ClientID: "foreign", RpID: "other-vendor"},
	}
	ts.signer = &fakeJWS{}
	ts.store = &recordingStore{RuntimeStoreProvider: inmemory.Initialize("test"), ttls: map[string]int64{}}
	ts.provider = newDeviceSecretProvider(ts.cfg, ts.signer, fakeJWE{}, clients, ts.store)
	ts.now = time.Now()
	ts.provider.now = func() time.Time { return ts.now }
}

func (ts *DeviceSecretProviderTestSuite) generate() *providers.DeviceSecret {
	ds, svcErr := ts.provider.GenerateDeviceSecret(context.Background(), &providers.DeviceSecretRequest{
		Subject: "psut-1", AuthID: "sid-1", ClientID: "super", Scopes: []string{"openid", "profile"},
		ACR: "mosip:idp:acr:generated-code", CnfJkt: "jkt-a", AttributeCacheID: "aci-1", AuthTime: ts.now.Unix(),
	})
	ts.Require().Nil(svcErr)
	return ds
}

func (ts *DeviceSecretProviderTestSuite) TestRoundTrip() {
	ds := ts.generate()
	ts.Equal(4, strings.Count(ds.Value, "."), "device secret is a compact JWE")
	ts.WithinDuration(ts.now.Add(time.Hour), ds.ExpiresAt, time.Second)

	claims, svcErr := ts.provider.ValidateDeviceSecret(context.Background(), "super", ds.Value)
	ts.Require().Nil(svcErr)
	ts.Equal("psut-1", claims.Subject)
	ts.Equal("sid-1", claims.SessionID)
	ts.Equal("super", claims.ClientID)
	ts.Equal([]string{"openid", "profile"}, claims.Scopes)
	ts.Equal("jkt-a", claims.CnfJkt)
	ts.Equal("aci-1", claims.AttributeCacheID)
	ts.Equal("mosip:idp:acr:generated-code", claims.ACR)
	ts.NotEmpty(claims.ID)
}

func (ts *DeviceSecretProviderTestSuite) TestGenerateRejectsIncompleteRequests() {
	_, svcErr := ts.provider.GenerateDeviceSecret(context.Background(), &providers.DeviceSecretRequest{
		Subject: "psut-1", AuthID: "sid-1", ClientID: "super",
	})
	ts.Require().NotNil(svcErr)
	ts.Equal(common.ClientErrorType, svcErr.Type)
}

func (ts *DeviceSecretProviderTestSuite) TestGenerateFailsClosedWhenSigningFails() {
	ts.signer.signErr = errors.New("hsm unavailable")
	_, svcErr := ts.provider.GenerateDeviceSecret(context.Background(), &providers.DeviceSecretRequest{
		Subject: "psut-1", AuthID: "sid-1", ClientID: "super", CnfJkt: "jkt-a",
	})
	ts.Require().NotNil(svcErr)
	ts.Equal(common.ServerErrorType, svcErr.Type)
}

func (ts *DeviceSecretProviderTestSuite) TestValidateRejectsForgedOrExpiredSecrets() {
	ds := ts.generate()
	parts := strings.Split(ds.Value, ".")

	unsigned, _ := base64.RawURLEncoding.DecodeString(parts[3])
	resigned := strings.TrimSuffix(string(unsigned), ".sig") + ".forged"
	parts[3] = base64.RawURLEncoding.EncodeToString([]byte(resigned))

	cases := map[string]string{
		"not a JWE":       "a.b.c",
		"undecryptable":   strings.Replace(ds.Value, "hdr.", "xxx.", 1),
		"bad signature":   strings.Join(parts, "."),
		"empty":           "",
		"garbage payload": "hdr.key.iv." + base64.RawURLEncoding.EncodeToString([]byte("h.bm90LWpzb24.sig")) + ".tag",
	}
	for name, secret := range cases {
		ts.Run(name, func() {
			_, svcErr := ts.provider.ValidateDeviceSecret(context.Background(), "super", secret)
			ts.Require().NotNil(svcErr)
			ts.Equal("invalid_device_secret", svcErr.Code)
		})
	}

	ts.Run("expired", func() {
		ts.now = ts.now.Add(2 * time.Hour)
		_, svcErr := ts.provider.ValidateDeviceSecret(context.Background(), "super", ds.Value)
		ts.Require().NotNil(svcErr)
		ts.Equal("device_secret_expired", svcErr.Code)
	})
}

func (ts *DeviceSecretProviderTestSuite) TestValidateRejectsSecretsOfAnotherIssuer() {
	ds := ts.generate()
	ts.cfg.Issuer = "https://another-esignet.example.com"
	_, svcErr := ts.provider.ValidateDeviceSecret(context.Background(), "super", ds.Value)
	ts.Require().NotNil(svcErr)
	ts.Equal("invalid_device_secret", svcErr.Code)
}

func (ts *DeviceSecretProviderTestSuite) TestRedemptionAllowList() {
	ds := ts.generate()
	cases := []struct {
		clientID string
		allowed  bool
		server   bool
	}{
		{clientID: "super", allowed: true},
		{clientID: "child", allowed: true},
		{clientID: "unlisted"},
		{clientID: "foreign"}, // allow-listed, but registered under another relying party
		{clientID: "unknown"},
		{clientID: "broken", server: true},
	}
	for _, tc := range cases {
		ts.Run(tc.clientID, func() {
			_, svcErr := ts.provider.ValidateDeviceSecret(context.Background(), tc.clientID, ds.Value)
			switch {
			case tc.allowed:
				ts.Nil(svcErr)
			case tc.server:
				ts.Require().NotNil(svcErr)
				ts.Equal(common.ServerErrorType, svcErr.Type)
			default:
				ts.Require().NotNil(svcErr)
				ts.Equal("native_sso_client_not_allowed", svcErr.Code)
			}
		})
	}
}

func (ts *DeviceSecretProviderTestSuite) TestRedeemOncePerClient() {
	ds := ts.generate()
	claims, svcErr := ts.provider.ValidateDeviceSecret(context.Background(), "child", ds.Value)
	ts.Require().Nil(svcErr)

	ts.Nil(ts.provider.MarkDeviceSecretUsed(context.Background(), claims, "child"))
	replay := ts.provider.MarkDeviceSecretUsed(context.Background(), claims, "child")
	ts.Require().NotNil(replay)
	ts.Equal("device_secret_already_redeemed", replay.Code)

	// Another app of the family can still join the session.
	ts.Nil(ts.provider.MarkDeviceSecretUsed(context.Background(), claims, "super"))

	session, svcErr := ts.provider.session(context.Background(), "sid-1")
	ts.Require().Nil(svcErr)
	ts.Equal([]string{"child", "super"}, session.RedeemedBy)
}

func (ts *DeviceSecretProviderTestSuite) TestOncePerClientLocksForTheDeviceSecretLifetime() {
	ds := ts.generate()
	claims, svcErr := ts.provider.ValidateDeviceSecret(context.Background(), "child", ds.Value)
	ts.Require().Nil(svcErr)
	ts.Require().Nil(ts.provider.MarkDeviceSecretUsed(context.Background(), claims, "child"))
	ts.InDelta(3600, ts.store.ttls[claims.ID+"|child"], 2)
}

func (ts *DeviceSecretProviderTestSuite) TestOncePerTokenLifetimeAllowsSignInAgainAfterExpiry() {
	ts.cfg.NativeSSO.RedemptionPolicy = config.NativeSSORedeemOncePerTokenLifetime
	ctx := context.Background()
	ds := ts.generate()
	claims, svcErr := ts.provider.ValidateDeviceSecret(ctx, "child", ds.Value)
	ts.Require().Nil(svcErr)

	ts.Require().Nil(ts.provider.MarkDeviceSecretUsed(ctx, claims, "child"))
	ts.EqualValues(120, ts.store.ttls[claims.ID+"|child"], "the lock lasts as long as the access token")

	replay := ts.provider.MarkDeviceSecretUsed(ctx, claims, "child")
	ts.Require().NotNil(replay, "a replay while the token is live is refused")
	ts.Equal("device_secret_already_redeemed", replay.Code)

	// The access token has expired: the lock is gone and the app signs in again silently.
	ts.Require().NoError(ts.store.Delete(ctx, nativeSSORedemptionNamespace, claims.ID+"|child"))
	ts.Nil(ts.provider.MarkDeviceSecretUsed(ctx, claims, "child"))

	session, svcErr := ts.provider.session(ctx, "sid-1")
	ts.Require().Nil(svcErr)
	ts.Equal([]string{"child"}, session.RedeemedBy, "a re-sign-in does not duplicate the session member")
}

func (ts *DeviceSecretProviderTestSuite) TestOncePerTokenLifetimeNeverOutlivesTheDeviceSecret() {
	ts.cfg.NativeSSO.RedemptionPolicy = config.NativeSSORedeemOncePerTokenLifetime
	for name, tokenTTL := range map[string]int64{"longer token": 7200, "unset token lifetime": 0} {
		ts.Run(name, func() {
			ts.cfg.JWT.ValidityPeriod = tokenTTL
			ds := ts.generate()
			claims, svcErr := ts.provider.ValidateDeviceSecret(context.Background(), "child", ds.Value)
			ts.Require().Nil(svcErr)
			ts.Require().Nil(ts.provider.MarkDeviceSecretUsed(context.Background(), claims, "child"))
			ts.InDelta(3600, ts.store.ttls[claims.ID+"|child"], 2)
		})
	}
}

func (ts *DeviceSecretProviderTestSuite) TestReusablePolicyAllowsRepeatedRedemption() {
	ts.cfg.NativeSSO.RedemptionPolicy = config.NativeSSORedeemReusable
	ds := ts.generate()
	claims, svcErr := ts.provider.ValidateDeviceSecret(context.Background(), "child", ds.Value)
	ts.Require().Nil(svcErr)
	ts.Nil(ts.provider.MarkDeviceSecretUsed(context.Background(), claims, "child"))
	ts.Nil(ts.provider.MarkDeviceSecretUsed(context.Background(), claims, "child"))
}

func (ts *DeviceSecretProviderTestSuite) TestMarkUsedRejectsExpiredClaims() {
	svcErr := ts.provider.MarkDeviceSecretUsed(context.Background(),
		&providers.DeviceSecretClaims{ID: "x", ExpiresAt: time.Now().Add(-time.Minute)}, "child")
	ts.Require().NotNil(svcErr)
	ts.Equal("device_secret_expired", svcErr.Code)
}

func (ts *DeviceSecretProviderTestSuite) TestEndSessionSignsOutTheWholeFamily() {
	ds := ts.generate()
	active, svcErr := ts.provider.IsSessionActive(context.Background(), "sid-1")
	ts.Require().Nil(svcErr)
	ts.True(active)

	claims, _ := ts.provider.ValidateDeviceSecret(context.Background(), "child", ds.Value)
	ts.Require().Nil(ts.provider.MarkDeviceSecretUsed(context.Background(), claims, "child"))

	members, svcErr := ts.provider.EndSession(context.Background(), ds.Value)
	ts.Require().Nil(svcErr)
	ts.Equal([]string{"super", "child"}, members)

	_, svcErr = ts.provider.ValidateDeviceSecret(context.Background(), "child", ds.Value)
	ts.Require().NotNil(svcErr)
	ts.Equal("native_sso_session_ended", svcErr.Code)

	active, svcErr = ts.provider.IsSessionActive(context.Background(), "sid-1")
	ts.Require().Nil(svcErr)
	ts.False(active)

	_, svcErr = ts.provider.EndSession(context.Background(), ds.Value)
	ts.Require().NotNil(svcErr)
	ts.Equal("native_sso_session_ended", svcErr.Code)
}

func (ts *DeviceSecretProviderTestSuite) TestNewSessionSupersedesOldDeviceSecret() {
	old := ts.generate()
	ts.generate() // a new login with the same sid replaces the session
	_, svcErr := ts.provider.ValidateDeviceSecret(context.Background(), "super", old.Value)
	ts.Require().NotNil(svcErr)
	ts.Equal("native_sso_session_ended", svcErr.Code)
}

func (ts *DeviceSecretProviderTestSuite) TestDisabledReturnsNilProvider() {
	ts.cfg.NativeSSO.Enabled = false
	ts.Nil(NewDeviceSecretProvider(ts.cfg, nil, nil, nil, nil))
	ts.Nil(NewNativeSSOConsentProvider(nil, nil, ts.cfg))
}
