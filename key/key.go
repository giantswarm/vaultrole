package key

import (
	"fmt"
)

func ListRolesPath(ID string) string {
	return fmt.Sprintf("pki-%s/roles/", ID)
}

func RoleName(ID string) string {
	return fmt.Sprintf("role-%s", ID)
}

func WriteRolePath(ID, roleName string) string {
	return fmt.Sprintf("pki-%s/roles/%s", ID, roleName)
}
