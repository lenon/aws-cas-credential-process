package keyring

import (
	"fmt"
	"strings"
	"time"
)

const (
	serviceKey         = "aws-cas-credential-process"
	usernameKey        = "username"
	passwordKey        = "password"
	accessKeyIdKey     = "AccessKeyId"
	secretAccessKeyKey = "SecretAccessKey"
	sessionTokenKey    = "SessionToken"
	expirationKey      = "Expiration"
)

type Keyring struct {
	backend keyringBackend
}

func Open() *Keyring {
	return &Keyring{backend: &backend{}}
}

func (k *Keyring) Get(key string) (string, error) {
	value, err := k.backend.Get(serviceKey, key)

	if err != nil {
		return "", fmt.Errorf("key not found: %s", key)
	}

	return value, nil
}

func (k *Keyring) GetUsername() (string, error) {
	return k.Get(usernameKey)
}

func (k *Keyring) GetPassword() (string, error) {
	return k.Get(passwordKey)
}

func namespacedKey(context, key string) string {
	return fmt.Sprintf("%s-%s", strings.ToLower(context), key)
}

func (k *Keyring) GetWithinContext(context, key string) (string, error) {
	namespacedKey := namespacedKey(context, key)
	return k.Get(namespacedKey)
}

func (k *Keyring) GetAccessKeyId(context string) (string, error) {
	return k.GetWithinContext(context, accessKeyIdKey)
}

func (k *Keyring) GetSecretAccessKey(context string) (string, error) {
	return k.GetWithinContext(context, secretAccessKeyKey)
}

func (k *Keyring) GetSessionToken(context string) (string, error) {
	return k.GetWithinContext(context, sessionTokenKey)
}

func (k *Keyring) GetExpiration(context string) (*time.Time, error) {
	str, err := k.GetWithinContext(context, expirationKey)
	if err != nil {
		return nil, err
	}

	time, err := time.Parse(time.RFC3339, str)
	if err != nil {
		return nil, err
	}

	return &time, nil
}

func (k *Keyring) Set(key, value string) error {
	if err := k.backend.Set(serviceKey, key, value); err != nil {
		return err
	}

	return nil
}

func (k *Keyring) SetUsername(username string) error {
	return k.Set(usernameKey, username)
}

func (k *Keyring) SetPassword(password string) error {
	return k.Set(passwordKey, password)
}

func (k *Keyring) SetWithinContext(context, key, value string) error {
	namespacedKey := namespacedKey(context, key)
	return k.Set(namespacedKey, value)
}

func (k *Keyring) SetAccessKeyId(context, value string) error {
	return k.SetWithinContext(context, accessKeyIdKey, value)
}

func (k *Keyring) SetSecretAccessKey(context, value string) error {
	return k.SetWithinContext(context, secretAccessKeyKey, value)
}

func (k *Keyring) SetSessionToken(context, value string) error {
	return k.SetWithinContext(context, sessionTokenKey, value)
}

func (k *Keyring) SetExpiration(context string, value *time.Time) error {
	strTime := value.Format(time.RFC3339)
	return k.SetWithinContext(context, expirationKey, strTime)
}

func (k *Keyring) DeleteAll() {
	// TO-DO: delete namespaced keys too
	k.backend.Delete(serviceKey, usernameKey)
	k.backend.Delete(serviceKey, passwordKey)
}
