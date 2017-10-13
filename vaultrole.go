package vaultrole

import (
	"github.com/giantswarm/microerror"
	vaultclient "github.com/hashicorp/vault/api"
)

type Config struct {
	VaultClient *vaultclient.Client

	PKIMountpoint string
}

func DefaultConfig() Config {
	config := Config{}

	return config
}

type VaultRole struct {
	vaultClient *vaultclient.Client

	pkiMountpoint string
}

func New(config Config) (*VaultRole, error) {
	if config.VaultClient == nil {
		return nil, microerror.Maskf(invalidConfigError, "Vault client must not be empty")
	}

	if config.PKIMountpoint == "" {
		return nil, microerror.Maskf(invalidConfigError, "PKIMountpoint must not be empty")
	}

	r := &VaultRole{
		vaultClient: config.VaultClient,

		pkiMountpoint: config.PKIMountpoint,
	}

	return r, nil
}
