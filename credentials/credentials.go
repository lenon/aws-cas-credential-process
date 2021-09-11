package credentials

import (
	"errors"
	"fmt"
	"strings"
	"time"

	gokr "github.com/zalando/go-keyring"
)

const (
	serviceKey         = "aws-web-sso-helper"
	usernameKey        = "username"
	passwordKey        = "password"
	accessKeyIdKey     = "AccessKeyId"
	secretAccessKeyKey = "SecretAccessKey"
	sessionTokenKey    = "SessionToken"
	expirationKey      = "Expiration"
)

type Credentials struct {
	keyring gokr.Keyring
}

func NewWithDefaults() *Credentials {
	return &Credentials{keyring: &keyring{}}
}

func (c *Credentials) Get(key string) (string, error) {
	value, err := c.keyring.Get(serviceKey, key)

	if err != nil {
		return "", errors.New(fmt.Sprintf("%s not found", key))
	}

	return value, nil
}

func (c *Credentials) GetUsername() (string, error) {
	return c.Get(usernameKey)
}

func (c *Credentials) GetPassword() (string, error) {
	return c.Get(passwordKey)
}

func namespacedKey(context, key string) string {
	return fmt.Sprintf("%s-%s", strings.ToLower(context), key)
}

func (c *Credentials) GetWithinContext(context, key string) (string, error) {
	namespacedKey := namespacedKey(context, key)
	return c.Get(namespacedKey)
}

func (c *Credentials) GetAccessKeyId(context string) (string, error) {
	return c.GetWithinContext(context, accessKeyIdKey)
}

func (c *Credentials) GetSecretAccessKey(context string) (string, error) {
	return c.GetWithinContext(context, secretAccessKeyKey)
}

func (c *Credentials) GetSessionToken(context string) (string, error) {
	return c.GetWithinContext(context, sessionTokenKey)
}

func (c *Credentials) GetExpiration(context string) (*time.Time, error) {
	str, err := c.GetWithinContext(context, expirationKey)
	if err != nil {
		return nil, err
	}

	time, err := time.Parse(time.RFC3339, str)
	if err != nil {
		return nil, err
	}

	return &time, nil
}

func (c *Credentials) Set(key, value string) error {
	if err := c.keyring.Set(serviceKey, key, value); err != nil {
		return err
	}

	return nil
}

func (c *Credentials) SetUsername(username string) error {
	return c.Set(usernameKey, username)
}

func (c *Credentials) SetPassword(password string) error {
	return c.Set(passwordKey, password)
}

func (c *Credentials) SetWithinContext(context, key, value string) error {
	namespacedKey := namespacedKey(context, key)
	return c.Set(namespacedKey, value)
}

func (c *Credentials) SetAccessKeyId(context, value string) error {
	return c.SetWithinContext(context, accessKeyIdKey, value)
}

func (c *Credentials) SetSecretAccessKey(context, value string) error {
	return c.SetWithinContext(context, secretAccessKeyKey, value)
}

func (c *Credentials) SetSessionToken(context, value string) error {
	return c.SetWithinContext(context, sessionTokenKey, value)
}

func (c *Credentials) SetExpiration(context string, value *time.Time) error {
	strTime := value.Format(time.RFC3339)
	return c.SetWithinContext(context, expirationKey, strTime)
}

func (c *Credentials) DeleteAll() {
	// TO-DO: delete namespaced keys too
	c.keyring.Delete(serviceKey, usernameKey)
	c.keyring.Delete(serviceKey, passwordKey)
}
