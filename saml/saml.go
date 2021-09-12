package saml

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go/aws/arn"
)

const awsRoleAttrName = "https://aws.amazon.com/SAML/Attributes/Role"

type response struct {
	XMLName   xml.Name   `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	Assertion *assertion `xml:"Assertion"`
}

type assertion struct {
	XMLName            xml.Name            `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	AttributeStatement *attributeStatement `xml:"AttributeStatement"`
}

type attributeStatement struct {
	XMLName    xml.Name    `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
	Attributes []attribute `xml:"Attribute"`
}

type attribute struct {
	XMLName         xml.Name         `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
	Name            string           `xml:"Name,attr"`
	AttributeValues []attributeValue `xml:"AttributeValue"`
}

type attributeValue struct {
	XMLName xml.Name `xml:"AttributeValue"`
	Value   string   `xml:",chardata"`
}

func Decode(base64response string) (*response, error) {
	decodedResponse, err := base64.StdEncoding.DecodeString(base64response)
	if err != nil {
		return nil, err
	}

	var resp response
	if err := xml.Unmarshal(decodedResponse, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

func (resp *response) GetAWSRoles() ([][]*arn.ARN, error) {
	var arns [][]*arn.ARN

	for _, attr := range resp.Assertion.AttributeStatement.Attributes {
		if attr.Name != awsRoleAttrName {
			continue
		}

		for _, role := range attr.AttributeValues {
			principal, roleToAssume, err := rolesFromSAMLAttr(role.Value)
			if err != nil {
				return nil, err
			}

			arns = append(arns, []*arn.ARN{principal, roleToAssume})
		}
	}

	if len(arns) < 1 {
		return nil, errors.New("expected to find at least one role in SAML response, found none")
	}

	return arns, nil
}

func (r *response) FindPrincipalAndRoleToAssume(roleName string) (string, string, error) {
	roles, err := r.GetAWSRoles()
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

	return "", "", errors.New(fmt.Sprintf("could not find AWS principal and role %s", roleName))
}
