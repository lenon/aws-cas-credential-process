package cas

import (
	"errors"
	"io"

	"github.com/antchfx/htmlquery"
)

func getSAMLResponseFromHTML(body io.Reader) (string, error) {
	doc, err := htmlquery.Parse(body)
	if err != nil {
		return "", err
	}

	input, err := htmlquery.Query(doc, "//input[@name=\"SAMLResponse\"]")
	if err != nil {
		return "", err
	}

	if input == nil {
		return "", errors.New("SAML response not found")
	}

	base64str := htmlquery.SelectAttr(input, "value")
	return base64str, nil
}
