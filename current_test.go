package vaultrole

import (
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/giantswarm/microerror"
	"github.com/hashicorp/vault/api"
)

func Test_vaultSecretToRole(t *testing.T) {
	testCases := []struct {
		name         string
		input        *api.Secret
		expectedRole Role
		errorMatcher func(error) bool
	}{
		{
			name: "case 0: test pre-vault-update with concatenated altnames in single string",
			input: &api.Secret{
				Data: map[string]interface{}{
					"allow_bare_domains": true,
					"allow_subdomains":   true,
					"allowed_domains":    "foo.com,bar.com,baz.com",
					"organization":       "Foobar",
					"ttl":                "3600s",
				},
			},
			expectedRole: Role{
				AllowBareDomains: true,
				AllowSubdomains:  true,
				AltNames:         []string{"bar.com", "baz.com"},
				Organizations:    []string{"Foobar"},
				TTL:              3600 * time.Second,
			},
			errorMatcher: nil,
		},
		{
			name: "case 1: test post-vault-update with altnames as slice of interfaces which are string underneath",
			input: &api.Secret{
				Data: map[string]interface{}{
					"allow_bare_domains": true,
					"allow_subdomains":   true,
					"allowed_domains":    []interface{}{"foo.com", "bar.com", "baz.com"},
					"organization":       "Foobar",
					"ttl":                "3600s",
				},
			},
			expectedRole: Role{
				AllowBareDomains: true,
				AllowSubdomains:  true,
				AltNames:         []string{"bar.com", "baz.com"},
				Organizations:    []string{"Foobar"},
				TTL:              3600 * time.Second,
			},
			errorMatcher: nil,
		},
		{
			name: "case 2: test with altnames as slice of string",
			input: &api.Secret{
				Data: map[string]interface{}{
					"allow_bare_domains": true,
					"allow_subdomains":   true,
					"allowed_domains":    []string{"foo.com", "bar.com", "baz.com"},
					"organization":       "Foobar",
					"ttl":                "3600s",
				},
			},
			expectedRole: Role{
				AllowBareDomains: true,
				AllowSubdomains:  true,
				AltNames:         []string{"bar.com", "baz.com"},
				Organizations:    []string{"Foobar"},
				TTL:              3600 * time.Second,
			},
			errorMatcher: nil,
		},
		{
			name: "case 3: test missing allow_bare_domains field causes invalidConfigError",
			input: &api.Secret{
				Data: map[string]interface{}{
					"allow_subdomains": true,
					"allowed_domains":  []string{"foo.com", "bar.com", "baz.com"},
					"organization":     "Foobar",
					"ttl":              "3600s",
				},
			},
			expectedRole: Role{},
			errorMatcher: IsInvalidConfig,
		},
		{
			name: "case 4: test missing allow_subdomains field causes invalidConfigError",
			input: &api.Secret{
				Data: map[string]interface{}{
					"allow_bare_domains": true,
					"allowed_domains":    []string{"foo.com", "bar.com", "baz.com"},
					"organization":       "Foobar",
					"ttl":                "3600s",
				},
			},
			expectedRole: Role{},
			errorMatcher: IsInvalidConfig,
		},
		{
			name: "case 5: test missing allowed_domains field causes invalidConfigError",
			input: &api.Secret{
				Data: map[string]interface{}{
					"allow_bare_domains": true,
					"allow_subdomains":   true,
					"organization":       "Foobar",
					"ttl":                "3600s",
				},
			},
			expectedRole: Role{},
			errorMatcher: IsInvalidConfig,
		},
		{
			name: "case 6: test missing organization field causes invalidConfigError",
			input: &api.Secret{
				Data: map[string]interface{}{
					"allow_bare_domains": true,
					"allow_subdomains":   true,
					"allowed_domains":    []string{"foo.com", "bar.com", "baz.com"},
					"ttl":                "3600s",
				},
			},
			expectedRole: Role{},
			errorMatcher: IsInvalidConfig,
		},
		{
			name: "case 6: test missing ttl field causes invalidConfigError",
			input: &api.Secret{
				Data: map[string]interface{}{
					"allow_bare_domains": true,
					"allow_subdomains":   true,
					"allowed_domains":    []string{"foo.com", "bar.com", "baz.com"},
					"organization":       "Foobar",
				},
			},
			expectedRole: Role{},
			errorMatcher: IsInvalidConfig,
		},
		{
			name: "case 7: test wrong type in allow_bare_domains field causes wrongTypeError",
			input: &api.Secret{
				Data: map[string]interface{}{
					"allow_bare_domains": int(42),
					"allow_subdomains":   true,
					"allowed_domains":    []string{"foo.com", "bar.com", "baz.com"},
					"organization":       "Foobar",
					"ttl":                "3600s",
				},
			},
			expectedRole: Role{},
			errorMatcher: IsWrongType,
		},
		{
			name: "case 8: test wrong type in allow_subdomains field causes wrongTypeError",
			input: &api.Secret{
				Data: map[string]interface{}{
					"allow_bare_domains": true,
					"allow_subdomains":   string("foobar"),
					"allowed_domains":    []string{"foo.com", "bar.com", "baz.com"},
					"organization":       "Foobar",
					"ttl":                "3600s",
				},
			},
			expectedRole: Role{},
			errorMatcher: IsWrongType,
		},
		{
			name: "case 9: test wrong type in allowed_domains field causes wrongTypeError",
			input: &api.Secret{
				Data: map[string]interface{}{
					"allow_bare_domains": true,
					"allow_subdomains":   true,
					"allowed_domains":    []int{1, 3, 5, 7, 11, 13},
					"organization":       "Foobar",
					"ttl":                "3600s",
				},
			},
			expectedRole: Role{},
			errorMatcher: IsWrongType,
		},
		{
			name: "case 10: test wrong type in organization field causes wrongTypeError",
			input: &api.Secret{
				Data: map[string]interface{}{
					"allow_bare_domains": true,
					"allow_subdomains":   true,
					"allowed_domains":    []string{"foo.com", "bar.com", "baz.com"},
					"organization":       struct{}{},
					"ttl":                "3600s",
				},
			},
			expectedRole: Role{},
			errorMatcher: IsWrongType,
		},
		{
			name: "case 11: test wrong type in ttl field causes wrongTypeError",
			input: &api.Secret{
				Data: map[string]interface{}{
					"allow_bare_domains": true,
					"allow_subdomains":   true,
					"allowed_domains":    []string{"foo.com", "bar.com", "baz.com"},
					"organization":       "Foobar",
					"ttl":                struct{}{},
				},
			},
			expectedRole: Role{},
			errorMatcher: IsWrongType,
		},
		{
			name: "case 12: test invalid ttl field causes wrongTypeError",
			input: &api.Secret{
				Data: map[string]interface{}{
					"allow_bare_domains": true,
					"allow_subdomains":   true,
					"allowed_domains":    []string{"foo.com", "bar.com", "baz.com"},
					"organization":       "Foobar",
					"ttl":                "unparseable",
				},
			},
			expectedRole: Role{},
			errorMatcher: func(e error) bool {
				if _, ok := microerror.Cause(e).(*strconv.NumError); ok {
					return true
				}
				return false
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			role, err := vaultSecretToRole(tc.input)

			switch {
			case err == nil && tc.errorMatcher == nil:
				// correct; carry on
			case err != nil && tc.errorMatcher == nil:
				t.Fatalf("error == %#v, want nil", err)
			case err == nil && tc.errorMatcher != nil:
				t.Fatalf("error == nil, want non-nil")
			case !tc.errorMatcher(err):
				t.Fatalf("error == %#v, want matching", err)
			}

			if !reflect.DeepEqual(role, tc.expectedRole) {
				t.Fatalf("Role == %#v, want %#v", role, tc.expectedRole)
			}
		})
	}
}
