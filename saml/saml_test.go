package saml

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func base64Sample(t *testing.T) string {
	data, err := ioutil.ReadFile("testdata/saml-response.base64")
	if err != nil {
		t.Fatal(err)
	}

	return string(data)
}

func TestDecodeError(t *testing.T) {
	response, err := Decode("invalid base 64")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "illegal base64 data")
	assert.Nil(t, response)
}

func TestDecodeSuccess(t *testing.T) {
	response, err := Decode(base64Sample(t))

	assert.Nil(t, err)
	assert.Len(t, response.Assertion.AttributeStatement.Attributes, 13)
}

func TestGetAWSRoles(t *testing.T) {
	response, _ := Decode(base64Sample(t))
	roles, err := response.GetAWSRoles()

	assert.Nil(t, err)
	assert.Len(t, roles, 2)
}

func TestFindPrincipalAndRoleToAssume(t *testing.T) {
	response, _ := Decode(base64Sample(t))
	principal, role, err := response.FindPrincipalAndRoleToAssume("firstrole")

	assert.Nil(t, err)
	assert.Equal(t, principal, "arn:aws:iam::111111111111:saml-provider/Example")
	assert.Equal(t, role, "arn:aws:iam::111111111111:role/FirstRole")
}

func TestFindPrincipalAndRoleToAssumeNotFound(t *testing.T) {
	response, _ := Decode(base64Sample(t))
	principal, role, err := response.FindPrincipalAndRoleToAssume("other")

	assert.EqualError(t, err, "could not find AWS principal and role other")
	assert.Empty(t, principal)
	assert.Empty(t, role)
}
