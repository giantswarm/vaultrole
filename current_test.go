package vaultrole

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/vault/api"
)

func Test_RoleExists(t *testing.T) {
	raw := strings.TrimSpace(`
{
	"data": {
		"keys": ["role-org-f1b776344f5a19dbc38243e915767ff2ef9234df"]
	}
}`)
	secret := api.Secret{}
	json.Unmarshal([]byte(raw), &secret)
	testCases := []struct {
		ID             string
		Organizations  []string
		ExpectedResult bool
	}{
		{
			ID:             "123",
			Organizations:  []string{"system:masters", "api"},
			ExpectedResult: true,
		},
	}

	for i, tc := range testCases {
		fmt.Println(tc.Organizations)
		result, err := roleExists(&secret, ExistsConfig{
			ID:            tc.ID,
			Organizations: tc.Organizations,
		})
		fmt.Println(tc.Organizations)
		if err != nil {
			t.Fatalf("case %d expected %#v got error %#v", i+1, tc.ExpectedResult, err)
		}
		if result != tc.ExpectedResult {
			t.Fatalf("case %d expected %#v got %#v", i+1, tc.ExpectedResult, result)
		}
	}

}
