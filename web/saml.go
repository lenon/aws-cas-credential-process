package web

import (
	"encoding/base64"
	"encoding/xml"
	"errors"

	"github.com/aws/aws-sdk-go/aws/arn"
)

const awsRoleAttrName = "https://aws.amazon.com/SAML/Attributes/Role"

type samlResponse struct {
	XMLName   xml.Name       `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	Assertion *samlAssertion `xml:"Assertion"`
}

type samlAssertion struct {
	XMLName            xml.Name                `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	AttributeStatement *samlAttributeStatement `xml:"AttributeStatement"`
}

type samlAttributeStatement struct {
	XMLName    xml.Name        `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
	Attributes []samlAttribute `xml:"Attribute"`
}

type samlAttribute struct {
	XMLName         xml.Name             `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
	Name            string               `xml:"Name,attr"`
	AttributeValues []samlAttributeValue `xml:"AttributeValue"`
}

type samlAttributeValue struct {
	XMLName xml.Name `xml:"AttributeValue"`
	Value   string   `xml:",chardata"`
}

func decodeFromBase64(base64str string) (*samlResponse, error) {
	decodedStr, err := base64.StdEncoding.DecodeString(base64str)
	if err != nil {
		return nil, err
	}

	var resp samlResponse
	if err := xml.Unmarshal(decodedStr, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

func (resp *samlResponse) getAWSRoles() ([][]*arn.ARN, error) {
	var arns [][]*arn.ARN

	for _, attr := range resp.Assertion.AttributeStatement.Attributes {
		if attr.Name != awsRoleAttrName {
			continue
		}

		for _, role := range attr.AttributeValues {
			principal, roleToAssume, err := extractRolesFromSAMLAttr(role.Value)
			if err != nil {
				return nil, err
			}

			arns = append(arns, []*arn.ARN{principal, roleToAssume})
		}
	}

	if len(arns) < 1 {
		return nil, errors.New("expected to find at least 1 role in SAML response, found 0")
	}

	return arns, nil
}

func (r *samlResponse) findPrincipalAndRoleToAssume(roleName string) (string, string, error) {
	roles, err := r.getAWSRoles()
	if err != nil {
		return "", "", err
	}

	for _, value := range roles {
		principal := value[0]
		role := value[1]

		if roleNameMatches(roleName, role) {
			return principal.String(), role.String(), nil
		}
	}

	return "", "", errors.New("could not find AWS principal and role name")
}
