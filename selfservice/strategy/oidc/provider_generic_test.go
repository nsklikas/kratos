// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc_test

import (
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/strategy/oidc"
	"github.com/ory/kratos/x"
	"github.com/ory/x/configx"
)

func makeOIDCClaims() json.RawMessage {
	claims, _ := json.Marshal(map[string]interface{}{
		"id_token": map[string]interface{}{
			"email": map[string]bool{
				"essential": true,
			},
			"email_verified": map[string]bool{
				"essential": true,
			},
		},
	})
	return claims
}

func makeAuthCodeURL(t *testing.T, r *login.Flow, reg *driver.RegistryDefault) string {
	p := oidc.NewProviderGenericOIDC(&oidc.Configuration{
		Provider:        "generic",
		ID:              "valid",
		ClientID:        "client",
		ClientSecret:    "secret",
		IssuerURL:       "https://accounts.google.com",
		Mapper:          "file://./stub/hydra.schema.json",
		RequestedClaims: makeOIDCClaims(),
	}, reg)
	c, err := p.(oidc.OAuth2Provider).OAuth2(t.Context())
	require.NoError(t, err)
	return c.AuthCodeURL("state", p.(oidc.OAuth2Provider).AuthCodeURLOptions(r)...)
}

func TestProviderGenericOIDC_AddAuthCodeURLOptions(t *testing.T) {
	conf, reg := pkg.NewFastRegistryWithMocks(t,
		configx.WithValue(config.ViperKeyPublicBaseURL, "https://ory.sh"))
	t.Run("case=redirectURI is public base url", func(t *testing.T) {
		r := &login.Flow{ID: x.NewUUID(), Refresh: true}
		actual, err := url.ParseRequestURI(makeAuthCodeURL(t, r, reg))
		require.NoError(t, err)
		assert.Contains(t, actual.Query().Get("redirect_uri"), "https://ory.sh")
	})

	t.Run("case=redirectURI is public base url", func(t *testing.T) {
		conf.MustSet(t.Context(), config.ViperKeyOIDCBaseRedirectURL, "https://example.org")
		t.Cleanup(func() {
			conf.MustSet(t.Context(), config.ViperKeyOIDCBaseRedirectURL, nil)
		})
		r := &login.Flow{ID: x.NewUUID(), Refresh: true}
		actual, err := url.ParseRequestURI(makeAuthCodeURL(t, r, reg))
		require.NoError(t, err)
		assert.Contains(t, actual.Query().Get("redirect_uri"), "https://example.org")
	})

	t.Run("case=expect prompt to be login with forced flag", func(t *testing.T) {
		r := &login.Flow{
			ID:      x.NewUUID(),
			Refresh: true,
		}
		assert.Contains(t, makeAuthCodeURL(t, r, reg), "prompt=login")
	})

	t.Run("case=expect prompt to not be login without forced flag", func(t *testing.T) {
		r := &login.Flow{
			ID: x.NewUUID(),
		}
		assert.NotContains(t, makeAuthCodeURL(t, r, reg), "prompt=login")
	})

	t.Run("case=expect requested claims to be set", func(t *testing.T) {
		r := &login.Flow{
			ID: x.NewUUID(),
		}
		assert.Contains(t, makeAuthCodeURL(t, r, reg), "claims="+url.QueryEscape(string(makeOIDCClaims())))
	})
}

func TestProviderGenericOIDC_Verify(t *testing.T) {
	t.Parallel()

	_, reg := pkg.NewVeryFastRegistryWithoutDB(t)
	issuer := newIDTokenIssuer(t, publicJWKS)
	otherKeys := newIDTokenIssuer(t, publicJWKS2)

	newProvider := func(c oidc.Configuration) oidc.Provider {
		c.Provider = "generic"
		c.ID = "generic"
		if c.ClientID == "" {
			c.ClientID = "client"
		}
		return oidc.NewProviderGenericOIDC(&c, reg)
	}
	claims := func(iss, aud string, exp time.Duration) jwt.RegisteredClaims {
		return jwt.RegisteredClaims{
			Issuer:    iss,
			Subject:   "acme@ory.sh",
			Audience:  jwt.ClaimStrings{aud},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(exp)),
		}
	}

	t.Run("case=is not a verifier unless ID token submission is enabled", func(t *testing.T) {
		_, ok := newProvider(oidc.Configuration{IssuerURL: issuer.URL}).(oidc.IDTokenVerifier)
		assert.False(t, ok)
	})

	t.Run("case=never skips the nonce", func(t *testing.T) {
		_, ok := newProvider(oidc.Configuration{IssuerURL: issuer.URL, IDTokenSubmissionEnabled: true}).(oidc.NonceValidationSkipper)
		assert.False(t, ok)
	})

	for _, tc := range []struct {
		name   string
		config oidc.Configuration
		claims jwt.RegisteredClaims
		err    string
	}{
		{
			name:   "valid",
			config: oidc.Configuration{IssuerURL: issuer.URL},
			claims: claims(issuer.URL, "client", time.Hour),
		},
		{
			name:   "valid for an additional audience",
			config: oidc.Configuration{IssuerURL: issuer.URL, AdditionalIDTokenAudiences: []string{"other-client"}},
			claims: claims(issuer.URL, "other-client", time.Hour),
		},
		{
			name:   "wrong issuer",
			config: oidc.Configuration{IssuerURL: issuer.URL},
			claims: claims("https://not-the-issuer.example.com", "client", time.Hour),
			err:    "oidc: id token issued by a different provider",
		},
		{
			name:   "wrong audience",
			config: oidc.Configuration{IssuerURL: issuer.URL},
			claims: claims(issuer.URL, "other-client", time.Hour),
			err:    "token audience didn't match allowed audiences: [client]",
		},
		{
			name:   "expired",
			config: oidc.Configuration{IssuerURL: issuer.URL},
			claims: claims(issuer.URL, "client", -time.Hour),
			err:    "oidc: token is expired",
		},
		{
			name:   "signed with a key the issuer does not publish",
			config: oidc.Configuration{IssuerURL: otherKeys.URL},
			claims: claims(otherKeys.URL, "client", time.Hour),
			err:    "failed to verify signature",
		},
		{
			name:   "issuer without discovery",
			config: oidc.Configuration{IssuerURL: issuer.URL + "/missing"},
			claims: claims(issuer.URL+"/missing", "client", time.Hour),
			err:    "Unable to initialize OpenID Connect Provider",
		},
	} {
		t.Run("case="+tc.name, func(t *testing.T) {
			tc.config.IDTokenSubmissionEnabled = true
			verifier, ok := newProvider(tc.config).(oidc.IDTokenVerifier)
			require.True(t, ok)

			c, err := verifier.Verify(t.Context(), createIDToken(t, tc.claims))
			if tc.err != "" {
				require.Error(t, err)
				assert.Contains(t, fmt.Sprintf("%+v", err), tc.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.claims.Issuer, c.Issuer)
			assert.Equal(t, "acme@ory.sh", c.Subject)
			assert.Equal(t, "acme@ory.sh", c.Email)
		})
	}
}
