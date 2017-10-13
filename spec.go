package vaultrole

type CreateConfig struct {
	AllowBareDomains bool
	AllowSubdomains  bool
	AllowedDomains   string
	ID               string
	Organizations    string
	TTL              string
}

type Interface interface {
	Create(config CreateConfig) error
	Exists(ID string) (bool, error)
}
