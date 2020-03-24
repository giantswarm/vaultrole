package key

import (
	"reflect"
	"testing"
)

func Test_AllowedDomains(t *testing.T) {
	testCases := []struct {
		ID               string
		CommonNameFormat string
		AltNames         []string
		ExpectedResult   string
	}{
		{
			ID:               "al9qy",
			CommonNameFormat: "%s.g8s.gigantic.io",
			AltNames: []string{
				"kubernetes",
				"kubernetes.default.svc.cluster.local",
			},
			ExpectedResult: "al9qy.g8s.gigantic.io,kubernetes,kubernetes.default.svc.cluster.local",
		},

		{
			ID:               "al9qy",
			CommonNameFormat: "%s.g8s.gigantic.io",
			AltNames:         []string{},
			ExpectedResult:   "al9qy.g8s.gigantic.io",
		},

		{
			ID:               "al9qy",
			CommonNameFormat: "%s.g8s.gigantic.io",
			AltNames:         nil,
			ExpectedResult:   "al9qy.g8s.gigantic.io",
		},
	}

	for i, tc := range testCases {
		result := AllowedDomains(tc.ID, tc.CommonNameFormat, tc.AltNames)

		if result != tc.ExpectedResult {
			t.Fatalf("case %d expected %#v got %#v", i+1, tc.ExpectedResult, result)
		}
	}
}

func Test_RoleName(t *testing.T) {
	testCases := []struct {
		ID             string
		Organizations  []string
		ExpectedResult string
	}{
		// Case 0: Without orgs, we should just get a role identified by the cluster id.
		{
			ID:             "123",
			Organizations:  nil,
			ExpectedResult: "role-123",
		},

		// Case 1: same as 0. but with initialized empty slice instead of nil.
		{
			ID:             "123",
			Organizations:  []string{},
			ExpectedResult: "role-123",
		},

		// Case 2: With orgs, we should get a role name that has a org hash in it.
		{
			ID: "123",
			Organizations: []string{
				"blue",
				"green",
			},
			ExpectedResult: "role-org-90b351b2fd11e3f6adabda139ebb28a73a8a6997c1db1a9f2214dd2775e9e953378a10003d7a42bc1efd0ee970f1a380ee9a4a39e1ef6b1ec79700d659fc77ba",
		},

		// Case 3: The order of the orgs should not impact the hash.
		{
			ID: "123",
			Organizations: []string{
				"green",
				"blue",
			},
			ExpectedResult: "role-org-90b351b2fd11e3f6adabda139ebb28a73a8a6997c1db1a9f2214dd2775e9e953378a10003d7a42bc1efd0ee970f1a380ee9a4a39e1ef6b1ec79700d659fc77ba",
		},

		// Case 4: A different orgs list should yield a different hash.
		{
			ID: "123",
			Organizations: []string{
				"green",
				"blue",
				"red",
			},
			ExpectedResult: "role-org-df4953e3027359c712f7baba9f289327f78d1a4834e3345806c53f61c29fd5479269ba73e4d1e899baad6de5a094c8bd89b40dc23e644399ca3b14c401e8f4f1",
		},

		// Case 5: A common case we see n production. The created hash here is of
		// interest to identify roles used for API certs.
		{
			ID: "al9qy",
			Organizations: []string{
				"api",
				"system:masters",
			},
			ExpectedResult: "role-org-7395c031992f478e2e0e8d3198272008d407e1bc209c0cd52048fdebdd4ac1e0afd1d904044d9a9a2b0fe515579a56a4daf2aea7092518218ef985371890109f",
		},
	}

	for i, tc := range testCases {
		result := RoleName(tc.ID, tc.Organizations)

		if result != tc.ExpectedResult {
			t.Fatalf("case %d expected %#v got %#v", i, tc.ExpectedResult, result)
		}
	}
}

func Test_ToAltNames(t *testing.T) {
	testCases := []struct {
		AllowedDomains   string
		ExpectedAltNames []string
	}{
		{
			AllowedDomains:   "",
			ExpectedAltNames: nil,
		},

		{
			AllowedDomains: "al9qy.g8s.gigantic.io,kubernetes,kubernetes.default.svc.cluster.local",
			ExpectedAltNames: []string{
				"kubernetes",
				"kubernetes.default.svc.cluster.local",
			},
		},

		{
			AllowedDomains: "kubernetes,kubernetes.default.svc.cluster.local",
			ExpectedAltNames: []string{
				"kubernetes.default.svc.cluster.local",
			},
		},
	}

	for i, tc := range testCases {
		result := ToAltNames(tc.AllowedDomains)

		if !reflect.DeepEqual(result, tc.ExpectedAltNames) {
			t.Fatalf("case %d expected %#v got %#v", i, tc.ExpectedAltNames, result)
		}
	}
}

func Test_ToOrganizations(t *testing.T) {
	testCases := []struct {
		Organizations         string
		ExpectedOrganizations []string
	}{
		{
			Organizations:         "",
			ExpectedOrganizations: nil,
		},

		{
			Organizations: "api,system:masters",
			ExpectedOrganizations: []string{
				"api",
				"system:masters",
			},
		},

		{
			Organizations: "api",
			ExpectedOrganizations: []string{
				"api",
			},
		},
	}

	for i, tc := range testCases {
		result := ToOrganizations(tc.Organizations)

		if !reflect.DeepEqual(result, tc.ExpectedOrganizations) {
			t.Fatalf("case %d expected %#v got %#v", i, tc.ExpectedOrganizations, result)
		}
	}
}
