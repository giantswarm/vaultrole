package key

import (
	"testing"
)

func Test_RoleName(t *testing.T) {
	testCases := []struct {
		ID             string
		Organizations  string
		ExpectedResult string
	}{
		// Case 1: Without orgs, we should just get a role identified by the cluster id.
		{
			ID:             "123",
			Organizations:  "",
			ExpectedResult: "role-123",
		},
		// Case 2: With orgs, we should get a role name that has a org hash in it.
		{
			ID:             "123",
			Organizations:  "blue,green",
			ExpectedResult: "role-org-ae04e382ff1b455a454bfde83bdda9dc8d077649",
		},
		// Case 3: The order of the orgs should not impact the hash.
		{
			ID:             "123",
			Organizations:  "green,blue",
			ExpectedResult: "role-org-ae04e382ff1b455a454bfde83bdda9dc8d077649",
		},
		// Case 4: A different orgs list should yield a different hash.
		{
			ID:             "123",
			Organizations:  "green,blue,red",
			ExpectedResult: "role-org-40c7be91742c1d2343d32ea489e169b1121bc674",
		},
	}

	for i, tc := range testCases {
		result := RoleName(tc.ID, tc.Organizations)

		if result != tc.ExpectedResult {
			t.Fatalf("case %d expected %#v got %#v", i+1, tc.ExpectedResult, result)
		}
	}
}
