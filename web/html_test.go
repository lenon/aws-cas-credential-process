package web

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func htmlSample() io.Reader {
	reader, err := os.Open("testdata/sso-response.html")

	if err != nil {
		panic(err)
	}
	return reader
}

func TestGetSAMLResponseFromHTML(t *testing.T) {
	base64str, err := getSAMLResponseFromHTML(htmlSample())

	assert.Nil(t, err)
	assert.Len(t, base64str, 9940)
}

func TestGetSAMLResponseFromHTMLError(t *testing.T) {
	base64str, err := getSAMLResponseFromHTML(strings.NewReader("foobar"))

	assert.EqualError(t, err, "SAML response not found")
	assert.Empty(t, base64str)
}
