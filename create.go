package vaultrole

import (
	"github.com/giantswarm/microerror"
)

func (r *VaultRole) Create(config CreateConfig) error {
	c := writeConfig{
		AllowBareDomains: config.AllowBareDomains,
		AllowSubdomains:  config.AllowSubdomains,
		AltNames:         config.AltNames,
		ID:               config.ID,
		Organizations:    config.Organizations,
		TTL:              config.TTL,
	}

	err := r.write(c)
	if err != nil {
		return microerror.Mask(err)
	}

	return nil
}
