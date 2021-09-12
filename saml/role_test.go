package saml

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRolesFromAttrInvalid(t *testing.T) {
	_, err := roleFromAttr("foobar")

	assert.EqualError(t, err, "expected to find principal and role to assume, found foobar")
}

func TestRolesFromAttrInvalidARNs(t *testing.T) {
	_, err := roleFromAttr("foobar,barbaz")

	assert.EqualError(t, err, "arn: invalid prefix")
}

func TestRolesFromAttrNoPrincipal(t *testing.T) {
	_, err := roleFromAttr("expected to find principal in arn:aws:iam::111111111111:role/MyRole,arn:aws:iam::111111111111:role/OtherRole")

	assert.EqualError(t, err, "arn: invalid prefix")
}

func TestRolesFromAttrNoRole(t *testing.T) {
	_, err := roleFromAttr("expected to find role in arn:aws:iam::111111111111:saml-provider/Example,arn:aws:iam::111111111111:saml-provider/Example")

	assert.EqualError(t, err, "arn: invalid prefix")
}

func TestRolesFromAttrValidARNs(t *testing.T) {
	role, err := roleFromAttr("arn:aws:iam::111111111111:role/MyRole,arn:aws:iam::111111111111:saml-provider/Example")

	assert.Nil(t, err)
	assert.Equal(t, role.principalARN, "arn:aws:iam::111111111111:saml-provider/Example")
	assert.Equal(t, role.roleARN, "arn:aws:iam::111111111111:role/MyRole")
}

func TestRolesFromAttrValidARNsReverse(t *testing.T) {
	role, err := roleFromAttr("arn:aws:iam::111111111111:saml-provider/Example,arn:aws:iam::111111111111:role/MyRole")

	assert.Nil(t, err)
	assert.Equal(t, role.principalARN, "arn:aws:iam::111111111111:saml-provider/Example")
	assert.Equal(t, role.roleARN, "arn:aws:iam::111111111111:role/MyRole")
}
