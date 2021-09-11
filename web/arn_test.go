package web

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/stretchr/testify/assert"
)

func TestExtractRolesFromSAMLAttrInvalid(t *testing.T) {
	_, _, err := extractRolesFromSAMLAttr("foobar")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected to find principal and role to assume, found foobar")
}

func TestExtractRolesFromSAMLAttrInvalidARNs(t *testing.T) {
	_, _, err := extractRolesFromSAMLAttr("foobar,barbaz")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "arn: invalid prefix")
}

func TestExtractRolesFromSAMLAttrValidARNs(t *testing.T) {
	principal, role, err := extractRolesFromSAMLAttr("arn:aws:iam::111111111111:saml-provider/Example,arn:aws:iam::111111111111:role/FirstRole")

	assert.Nil(t, err)
	assert.Equal(t, principal.String(), "arn:aws:iam::111111111111:saml-provider/Example")
	assert.Equal(t, role.String(), "arn:aws:iam::111111111111:role/FirstRole")
}

func TestRoleNameMatches(t *testing.T) {
	roleARN, _ := arn.Parse("arn:aws:iam::111111111111:role/FirstRole")

	assert.False(t, roleNameMatches("foobar", &roleARN))
	assert.True(t, roleNameMatches("FirstRole", &roleARN))
	assert.True(t, roleNameMatches("firstrole", &roleARN))
}
