package saml

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws/arn"
)

type role struct {
	principalARN string
	roleARN      string
}

func roleFromAttr(roleAttr string) (*role, error) {
	chunks := strings.Split(roleAttr, ",")

	if len(chunks) != 2 {
		return nil, fmt.Errorf("expected to find principal and role to assume, found %s", roleAttr)
	}

	var principalARN string
	var roleARN string

	// There is no specific order in which roles must appear, so it can be
	// saml-provider then role or role then saml-provider. The doc does not
	// mention anything in this regard either, so we need to check which one is
	// which.
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml_assertions.html#saml_role-attribute
	for _, role := range chunks {
		arn, err := arn.Parse(role)
		if err != nil {
			return nil, err
		}

		if arn.Service == "iam" && strings.HasPrefix(arn.Resource, "saml-provider/") {
			principalARN = arn.String()
		}

		if arn.Service == "iam" && strings.HasPrefix(arn.Resource, "role/") {
			roleARN = arn.String()
		}
	}

	if principalARN == "" {
		return nil, fmt.Errorf("expected to find principal in %s", roleAttr)
	}

	if roleARN == "" {
		return nil, fmt.Errorf("expected to find role in %s", roleAttr)
	}

	return &role{
		roleARN:      roleARN,
		principalARN: principalARN,
	}, nil
}
