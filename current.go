package vaultrole

import (
	"github.com/giantswarm/microerror"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/parseutil"

	"github.com/giantswarm/vaultrole/key"
)

func (r *VaultRole) Exists(config ExistsConfig) (bool, error) {
	// Check if a PKI for the given cluster ID exists.
	secret, err := r.vaultClient.Logical().List(key.ListRolesPath(config.ID))
	if IsNoVaultHandlerDefined(err) {
		return false, nil
	} else if err != nil {
		return false, microerror.Mask(err)
	}

	// In case there is not a single role for this PKI backend, secret is nil.
	if secret == nil {
		return false, nil
	}

	// When listing roles a list of role names is returned. Here we iterate over
	// this list and if we find the desired role name, it means the role has
	// already been created.
	if keys, ok := secret.Data["keys"]; ok {
		if list, ok := keys.([]interface{}); ok {
			for _, k := range list {
				if str, ok := k.(string); ok && str == key.RoleName(config.ID, config.Organizations) {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

type role struct {
	AllowBareDomains bool   `json:"allow_bare_domains"`
	AllowSubdomains  bool   `json:"allow_subdomains"`
	AllowedDomains   string `json:"allowed_domains"`
	Organizations    string `json:"organization"` // NOTE the singular form here.
	TTL              string `json:"ttl"`
}

func (r *VaultRole) Search(config SearchConfig) (Role, error) {
	// Check if a PKI for the given cluster ID exists.
	secret, err := r.vaultClient.Logical().Read(key.ReadRolePath(config.ID, config.Organizations))
	if IsNoVaultHandlerDefined(err) {
		return Role{}, microerror.Maskf(notFoundError, "no vault handler defined")
	} else if err != nil {
		return Role{}, microerror.Mask(err)
	}

	// In case there is not a single role for this PKI backend, secret is nil.
	if secret == nil {
		return Role{}, microerror.Maskf(notFoundError, "no vault secret at path '%s'", key.RoleName(config.ID, config.Organizations))
	}

	role, err := vaultSecretToRole(secret)
	if err != nil {
		return Role{}, microerror.Mask(err)
	}

	role.ID = config.ID
	return role, nil
}

// vaultSecretToRole makes required type casts / type checks and parsing to
// extract role information from Vault api.Secret.
func vaultSecretToRole(secret *api.Secret) (Role, error) {
	var role Role

	if allowBareDomains, ok := secret.Data["allow_bare_domains"].(bool); ok {
		role.AllowBareDomains = allowBareDomains
	} else {
		return Role{}, microerror.Maskf(wrongTypeError, "Vault secret.Data[\"allow_bare_domains\"] type is %T, expected %T", secret.Data["allow_bare_domains"], allowBareDomains)
	}

	if allowSubdomains, ok := secret.Data["allow_subdomains"].(bool); ok {
		role.AllowSubdomains = allowSubdomains
	} else {
		return Role{}, microerror.Maskf(wrongTypeError, "Vault secret.Data[\"allow_subdomains\"] type is %T, expected %T", secret.Data["allow_subdomains"], allowSubdomains)
	}

	// Types in secret.Data["allowed_domains"] differ between versions of
	// Vault / configuration of g8s. Try couple different formats before
	// giving up.
	var allowedDomains []string
	if one_allowed_domain, ok := secret.Data["allowed_domains"].(string); ok {
		allowedDomains = append(allowedDomains, one_allowed_domain)
	} else if multiple_allowed_domains, ok := secret.Data["allowed_domains"].([]string); ok {
		allowedDomains = append(allowedDomains, multiple_allowed_domains...)
	} else if interfaces, ok := secret.Data["allowed_domains"].([]interface{}); ok {
		for i, val := range interfaces {
			if s, ok := val.(string); ok {
				allowedDomains = append(allowedDomains, s)
			} else {
				return Role{}, microerror.Maskf(wrongTypeError, "Vault secret.Data[\"allowed_domains\"][%d] has unexpected type '%T'. It's not string nor []string.", i, val)
			}
		}
	} else {
		return Role{}, microerror.Maskf(wrongTypeError, "Vault secret.Data[\"allowed_domains\"] type is '%T'. It's not string, []string nor []interface{} (masking strings).", secret.Data["allowed_domains"])
	}

	// TODO: Why first one is dropped (this was in key.ToAltNames()?
	role.AltNames = allowedDomains[1:]

	if organization, ok := secret.Data["organization"].(string); ok {
		role.Organizations = key.ToOrganizations(organization)
	} else {
		return Role{}, microerror.Maskf(wrongTypeError, "Vault secret.Data[\"organization\"] type is %T, expected %T", secret.Data["organization"], organization)
	}

	if ttl, ok := secret.Data["ttl"].(string); ok {
		ttl, err := parseutil.ParseDurationSecond(role.TTL)
		if err != nil {
			return Role{}, microerror.Mask(err)
		}

		role.TTL = ttl
	} else {
		return Role{}, microerror.Maskf(wrongTypeError, "Vault secret.Data[\"ttl\"] type is %T, expected %T", secret.Data["ttl"], ttl)
	}

	return role, nil
}
