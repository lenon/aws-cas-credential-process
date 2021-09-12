package cas

import (
	"errors"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type httpClientMock struct {
	mock.Mock
}

func (m *httpClientMock) Do(req *http.Request) (*http.Response, error) {
	args := m.Called(req)

	if args.Error(1) != nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*http.Response), args.Error(1)
}

func buildCAS() (*httpClientMock, *CAS) {
	httpmock := &httpClientMock{}
	cas := &CAS{
		URL:        "http://localhost",
		HTTPClient: httpmock,
	}

	return httpmock, cas
}

func bodySample() *os.File {
	reader, err := os.Open("testdata/sso-response.html")
	if err != nil {
		panic(err)
	}
	return reader
}

func TestAuthError(t *testing.T) {
	httpmock, cas := buildCAS()
	httpmock.On("Do", mock.AnythingOfType("*http.Request")).Return(nil, errors.New("something went wrong"))

	_, err := cas.Auth("alice", "w0nd3rl4nd")

	assert.EqualError(t, err, "something went wrong")
	httpmock.AssertExpectations(t)
}

func TestAuthSuccess(t *testing.T) {
	httpmock, cas := buildCAS()
	httpresp := &http.Response{
		StatusCode: 200,
		Body:       bodySample(),
	}
	reqMatcher := func(req *http.Request) bool {
		return req.URL.String() == cas.URL &&
			req.Header.Get("Content-Type") == "application/cas" &&
			req.Header.Get("Authorization") == "Basic YWxpY2U6dzBuZDNybDRuZA=="
	}

	httpmock.On("Do", mock.MatchedBy(reqMatcher)).Return(httpresp, nil)

	resp, err := cas.Auth("alice", "w0nd3rl4nd")

	assert.Nil(t, err)
	assert.NotEmpty(t, resp)
	httpmock.AssertExpectations(t)
}
