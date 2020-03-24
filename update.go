package vaultrole

import (
	"github.com/giantswarm/microerror"
)

func (r *VaultRole) Update(config UpdateConfig) error {
	// Check if the requested role exists.
	{
		c := ExistsConfig{
			ID:            config.ID,
			Organizations: config.Organizations,
		}
		exists, err := r.Exists(c)
		if err != nil {
			return microerror.Mask(err)
		}
		if !exists {
			return microerror.Maskf(notFoundError, "cannot update Vault role '%s'", config.ID)
		}
	}

	// Update the requested role if it exists.
	{
		c := writeConfig(config)

		err := r.write(c)
		if err != nil {
			return microerror.Mask(err)
		}
	}

	return nil
}
