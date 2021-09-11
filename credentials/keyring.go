package credentials

import gokr "github.com/zalando/go-keyring"

type keyring struct{}

func (k *keyring) Get(service, key string) (string, error) {
	return gokr.Get(service, key)
}

func (k *keyring) Set(service, key, value string) error {
	return gokr.Set(service, key, value)
}

func (k *keyring) Delete(service, key string) error {
	return gokr.Delete(service, key)
}
