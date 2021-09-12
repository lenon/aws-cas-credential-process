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

func TestFindRole(t *testing.T) {
	response, _ := Decode(base64Sample(t))
	role, err := response.FindRole("arn:aws:iam::111111111111:role/FirstRole")

	assert.Nil(t, err)
	assert.Equal(t, role.PrincipalARN, "arn:aws:iam::111111111111:saml-provider/Example")
	assert.Equal(t, role.RoleARN, "arn:aws:iam::111111111111:role/FirstRole")
}

func TestFindRoleNotFound(t *testing.T) {
	response, _ := Decode(base64Sample(t))
	role, err := response.FindRole("other")

	assert.EqualError(t, err, "could not find role: other")
	assert.Nil(t, role)
}
