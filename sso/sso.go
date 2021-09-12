package sso

import (
	"errors"
	"time"

	"github.com/lenon/aws-cas-credential-process/cas"
	"github.com/lenon/aws-cas-credential-process/keyring"
	"github.com/lenon/aws-cas-credential-process/saml"
	"github.com/lenon/aws-cas-credential-process/sts"
)

type SSO struct {
	URL     string
	RoleARN string
	Keyring *keyring.Keyring
	CAS     *cas.CAS
}

func (s *SSO) CachedLogin() *sts.Credentials {
	expiration, err := s.Keyring.GetExpiration(s.RoleARN)
	if err != nil {
		// no expiration value stored, can't use cached login as there isn't one
		return nil
	}

	expirationWindow := 1 * time.Minute
	expWithWindow := expiration.Add(-expirationWindow)

	if time.Now().After(expWithWindow) {
		// stored keys are expired, should proceed to login again
		return nil
	}

	accessKeyId, err := s.Keyring.GetAccessKeyId(s.RoleARN)
	if err != nil {
		return nil
	}

	secretAccessKey, err := s.Keyring.GetSecretAccessKey(s.RoleARN)
	if err != nil {
		return nil
	}

	sessionToken, err := s.Keyring.GetSessionToken(s.RoleARN)
	if err != nil {
		return nil
	}

	return &sts.Credentials{
		AccessKeyId:     accessKeyId,
		SecretAccessKey: secretAccessKey,
		SessionToken:    sessionToken,
		Expiration:      *expiration,
	}
}

func (s *SSO) Login() (*sts.Credentials, error) {
	username, err := s.Keyring.GetUsername()
	if err != nil {
		return nil, errors.New("missing AWS username, please run 'aws-cas-credential-process store' to configure it")
	}

	password, err := s.Keyring.GetPassword()
	if err != nil {
		return nil, errors.New("missing AWS password, please run 'aws-cas-credential-process store' to configure it")
	}

	samlResponseBase64, err := s.CAS.Auth(username, password)
	if err != nil {
		return nil, err
	}

	samlResponse, err := saml.Decode(samlResponseBase64)
	if err != nil {
		return nil, err
	}

	role, err := samlResponse.FindRole(s.RoleARN)
	if err != nil {
		return nil, err
	}

	credentials, err := sts.AssumeRole(role.PrincipalARN, role.RoleARN, samlResponseBase64)
	if err != nil {
		return nil, err
	}

	if err := s.Keyring.SetAccessKeyId(s.RoleARN, credentials.AccessKeyId); err != nil {
		return nil, err
	}

	if err := s.Keyring.SetSecretAccessKey(s.RoleARN, credentials.SecretAccessKey); err != nil {
		return nil, err
	}

	if err := s.Keyring.SetSessionToken(s.RoleARN, credentials.SessionToken); err != nil {
		return nil, err
	}

	if err := s.Keyring.SetExpiration(s.RoleARN, &credentials.Expiration); err != nil {
		return nil, err
	}

	return credentials, nil
}
