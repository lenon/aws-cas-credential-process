package web

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/suite"
)

type TestSuite struct {
	suite.Suite
	base64sample string
}

func (s *TestSuite) SetupTest() {
	data, err := ioutil.ReadFile("testdata/saml-response.base64")
	if err != nil {
		s.T().Fatal(err)
	}

	s.base64sample = string(data)
}

func (s *TestSuite) TestDecodeFromBase64Error() {
	samlresp, err := decodeFromBase64("invalid base 64")

	s.Error(err)
	s.Contains(err.Error(), "illegal base64 data")
	s.Nil(samlresp)
}

func (s *TestSuite) TestDecodeFromBase64Success() {
	samlresp, err := decodeFromBase64(s.base64sample)

	s.Nil(err)
	s.Len(samlresp.Assertion.AttributeStatement.Attributes, 13)
}

func (s *TestSuite) TestGetAWSRoles() {
	samlresp, _ := decodeFromBase64(s.base64sample)
	roles, err := samlresp.getAWSRoles()

	s.Nil(err)
	s.Len(roles, 2)
}

func (s *TestSuite) TestFindPrincipalAndRoleToAssume() {
	samlresp, _ := decodeFromBase64(s.base64sample)
	principal, role, err := samlresp.findPrincipalAndRoleToAssume("firstrole")

	s.Nil(err)
	s.Equal(principal, "arn:aws:iam::111111111111:saml-provider/Example")
	s.Equal(role, "arn:aws:iam::111111111111:role/FirstRole")
}

func (s *TestSuite) TestFindPrincipalAndRoleToAssumeNotFound() {
	samlresp, _ := decodeFromBase64(s.base64sample)
	principal, role, err := samlresp.findPrincipalAndRoleToAssume("other")

	s.EqualError(err, "could not find AWS principal and role name")
	s.Empty(principal)
	s.Empty(role)
}

func TestSaml(t *testing.T) {
	suite.Run(t, new(TestSuite))
}
