package keyring

import gokr "github.com/zalando/go-keyring"

type keyringBackend interface {
	Get(service, key string) (string, error)
	Set(service, key, value string) error
	Delete(service, key string) error
}

type backend struct{}

func (b *backend) Get(service, key string) (string, error) {
	return gokr.Get(service, key)
}

func (b *backend) Set(service, key, value string) error {
	return gokr.Set(service, key, value)
}

func (b *backend) Delete(service, key string) error {
	return gokr.Delete(service, key)
}
