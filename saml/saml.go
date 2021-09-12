package saml

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
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

func (resp *response) GetRoles() ([]*role, error) {
	var arns []*role

	for _, attr := range resp.Assertion.AttributeStatement.Attributes {
		// There are multiple attributes in the response. We are only interested
		// in the one that contains a list of roles that the user can assume.
		if attr.Name != awsRoleAttrName {
			continue
		}

		for _, roleAttr := range attr.AttributeValues {
			role, err := roleFromAttr(roleAttr.Value)
			if err != nil {
				return nil, err
			}

			arns = append(arns, role)
		}
	}

	if len(arns) < 1 {
		return nil, errors.New("expected to find at least one role in SAML response, found none")
	}

	return arns, nil
}

func (r *response) FindRole(roleARN string) (*role, error) {
	roles, err := r.GetRoles()
	if err != nil {
		return nil, err
	}

	for _, role := range roles {
		if role.RoleARN == roleARN {
			return role, nil
		}
	}

	return nil, fmt.Errorf("could not find role: %s", roleARN)
}
