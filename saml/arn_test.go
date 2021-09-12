package saml

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/stretchr/testify/assert"
)

func TestRolesFromSAMLAttrInvalid(t *testing.T) {
	_, _, err := rolesFromSAMLAttr("foobar")

	assert.EqualError(t, err, "expected to find principal and role to assume, found foobar")
}

func TestRolesFromSAMLAttrInvalidARNs(t *testing.T) {
	_, _, err := rolesFromSAMLAttr("foobar,barbaz")

	assert.EqualError(t, err, "arn: invalid prefix")
}

func TestRolesFromSAMLAttrValidARNs(t *testing.T) {
	principal, role, err := rolesFromSAMLAttr("arn:aws:iam::111111111111:saml-provider/Example,arn:aws:iam::111111111111:role/FirstRole")

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
