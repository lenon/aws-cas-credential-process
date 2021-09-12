package cas

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

type httpClient interface {
	Do(*http.Request) (*http.Response, error)
}

type CAS struct {
	HTTPClient httpClient
	URL        string
}

func New(url string) *CAS {
	return &CAS{
		URL: url,
		HTTPClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

func authorizationHeader(username, password string) string {
	credentials := fmt.Sprintf("%s:%s", username, password)
	base64auth := base64.StdEncoding.EncodeToString([]byte(credentials))

	return fmt.Sprintf("Basic %s", base64auth)
}

func (c *CAS) Auth(username, password string) (string, error) {
	req, err := http.NewRequest("GET", c.URL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Add("Content-Type", "application/cas")
	req.Header.Add("Authorization", authorizationHeader(username, password))

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}

	samlResponseBase64, err := getSAMLResponseFromHTML(resp.Body)
	if err != nil {
		return "", err
	}

	return samlResponseBase64, nil
}
