/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package engine

import (
	"context"
	"testing"

	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"

	"github.com/mosip/esignet/internal/config"
	"github.com/mosip/esignet/internal/engine/runtimestores/inmemory"
)

// FuzzValidateDeviceSecret checks that no input other than a device secret this provider issued is
// ever accepted, and that malformed input never panics.
func FuzzValidateDeviceSecret(f *testing.F) {
	cfg := &config.AppConfig{
		Issuer: "https://esignet.example.com",
		NativeSSO: config.NativeSSOConfig{
			Enabled: true, DeviceSecretValiditySecs: 3600, EncryptionReferenceID: "NATIVE_SSO",
			RedemptionPolicy: config.NativeSSORedeemOncePerClient,
		},
	}
	provider := newDeviceSecretProvider(cfg, &fakeJWS{}, fakeJWE{},
		fakeClients{"super": {ClientID: "super", RpID: "acme"}}, inmemory.Initialize("fuzz"))
	issued, svcErr := provider.GenerateDeviceSecret(context.Background(), &providers.DeviceSecretRequest{
		Subject: "psut-1", AuthID: "sid-1", ClientID: "super", Scopes: []string{"openid"}, CnfJkt: "jkt-a",
	})
	if svcErr != nil {
		f.Fatal(svcErr)
	}

	f.Add(issued.Value)
	f.Add("hdr.key.iv.ct.tag")
	f.Add("")
	f.Add("....")
	f.Add(issued.Value[:len(issued.Value)/2])

	f.Fuzz(func(t *testing.T, secret string) {
		claims, svcErr := provider.ValidateDeviceSecret(context.Background(), "super", secret)
		if svcErr == nil && secret != issued.Value {
			t.Fatalf("accepted a device secret that was never issued: %q -> %+v", secret, claims)
		}
	})
}
