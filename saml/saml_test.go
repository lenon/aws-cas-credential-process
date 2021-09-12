package saml

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

func (s *TestSuite) TestDecodeError() {
	response, err := Decode("invalid base 64")

	s.Error(err)
	s.Contains(err.Error(), "illegal base64 data")
	s.Nil(response)
}

func (s *TestSuite) TestDecodeSuccess() {
	response, err := Decode(s.base64sample)

	s.Nil(err)
	s.Len(response.Assertion.AttributeStatement.Attributes, 13)
}

func (s *TestSuite) TestGetAWSRoles() {
	response, _ := Decode(s.base64sample)
	roles, err := response.GetAWSRoles()

	s.Nil(err)
	s.Len(roles, 2)
}

func (s *TestSuite) TestFindPrincipalAndRoleToAssume() {
	response, _ := Decode(s.base64sample)
	principal, role, err := response.FindPrincipalAndRoleToAssume("firstrole")

	s.Nil(err)
	s.Equal(principal, "arn:aws:iam::111111111111:saml-provider/Example")
	s.Equal(role, "arn:aws:iam::111111111111:role/FirstRole")
}

func (s *TestSuite) TestFindPrincipalAndRoleToAssumeNotFound() {
	response, _ := Decode(s.base64sample)
	principal, role, err := response.FindPrincipalAndRoleToAssume("other")

	s.EqualError(err, "could not find AWS principal and role other")
	s.Empty(principal)
	s.Empty(role)
}

func TestSaml(t *testing.T) {
	suite.Run(t, new(TestSuite))
}
