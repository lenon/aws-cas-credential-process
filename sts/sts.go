package sts

import (
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

type Credentials struct {
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

func AssumeRole(principal, role, samlAssertion string) (*Credentials, error) {
	session, err := session.NewSession()
	if err != nil {
		return nil, err
	}

	svc := sts.New(session)
	resp, err := svc.AssumeRoleWithSAML(&sts.AssumeRoleWithSAMLInput{
		PrincipalArn:  &principal,
		RoleArn:       &role,
		SAMLAssertion: &samlAssertion,
	})
	if err != nil {
		return nil, err
	}

	return &Credentials{
		AccessKeyId:     *resp.Credentials.AccessKeyId,
		SecretAccessKey: *resp.Credentials.SecretAccessKey,
		SessionToken:    *resp.Credentials.SessionToken,
		Expiration:      *resp.Credentials.Expiration,
	}, nil
}
