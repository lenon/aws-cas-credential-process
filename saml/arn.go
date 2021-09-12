package saml

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws/arn"
)

func rolesFromSAMLAttr(principalAndRole string) (*arn.ARN, *arn.ARN, error) {
	chunks := strings.Split(principalAndRole, ",")

	if len(chunks) != 2 {
		return nil, nil, errors.New(fmt.Sprintf("expected to find principal and role to assume, found %s", principalAndRole))
	}

	principal, err := arn.Parse(chunks[0])
	if err != nil {
		return nil, nil, err
	}

	role, err := arn.Parse(chunks[1])
	if err != nil {
		return nil, nil, err
	}

	return &principal, &role, nil
}

func roleNameMatches(roleName string, roleARN *arn.ARN) bool {
	return fmt.Sprintf("role/%s", strings.ToLower(roleName)) == strings.ToLower(roleARN.Resource)
}
