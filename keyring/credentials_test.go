package keyring

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type keyringMock struct {
	mock.Mock
}

func (m *keyringMock) Get(service, key string) (string, error) {
	args := m.Called(service, key)
	return args.String(0), args.Error(1)
}

func (m *keyringMock) Set(service, key, value string) error {
	args := m.Called(service, key, value)
	return args.Error(0)
}

func (m *keyringMock) Delete(service, key string) error {
	args := m.Called(service, key)
	return args.Error(0)
}

type TestSuite struct {
	suite.Suite

	keyringMock *keyringMock
	credentials *Credentials
}

func (s *TestSuite) SetupTest() {
	s.keyringMock = new(keyringMock)
	s.credentials = &Credentials{keyring: s.keyringMock}
}

func (s *TestSuite) TestGetError() {
	s.keyringMock.On("Get", "aws-web-sso-helper", "username").Return("", errors.New("something went wrong"))

	username, err := s.credentials.Get("username")

	s.Empty(username)
	s.EqualError(err, "username not found")
	s.keyringMock.AssertExpectations(s.T())
}

func (s *TestSuite) TestGetWithSuccess() {
	s.keyringMock.On("Get", "aws-web-sso-helper", "username").Return("alice", nil)

	username, err := s.credentials.Get("username")

	s.Equal(username, "alice")
	s.Nil(err)
	s.keyringMock.AssertExpectations(s.T())
}

func (s *TestSuite) TestGetWithinContextError() {
	s.keyringMock.On("Get", "aws-web-sso-helper", "myrole-AccessKeyId").Return("", errors.New("something went wrong"))

	value, err := s.credentials.GetWithinContext("MyRole", "AccessKeyId")

	s.Empty(value)
	s.EqualError(err, "myrole-AccessKeyId not found")
	s.keyringMock.AssertExpectations(s.T())
}

func (s *TestSuite) TestGetWithinContextWithSuccess() {
	s.keyringMock.On("Get", "aws-web-sso-helper", "myrole-AccessKeyId").Return("foobarbaz", nil)

	value, err := s.credentials.GetWithinContext("MyRole", "AccessKeyId")

	s.Equal(value, "foobarbaz")
	s.Nil(err)
	s.keyringMock.AssertExpectations(s.T())
}

func (s *TestSuite) TestGetExpiration() {
	s.keyringMock.On("Get", "aws-web-sso-helper", "myrole-Expiration").Return("2009-11-10T23:00:00Z", nil)

	value, err := s.credentials.GetExpiration("MyRole")
	expected := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)

	s.Equal(value, &expected)
	s.Nil(err)
	s.keyringMock.AssertExpectations(s.T())
}

func (s *TestSuite) TestSetError() {
	s.keyringMock.On("Set", "aws-web-sso-helper", "username", "alice").Return(errors.New("something went wrong"))

	err := s.credentials.Set("username", "alice")

	s.EqualError(err, "something went wrong")
	s.keyringMock.AssertExpectations(s.T())
}

func (s *TestSuite) TestSetSuccess() {
	s.keyringMock.On("Set", "aws-web-sso-helper", "username", "alice").Return(nil)

	err := s.credentials.Set("username", "alice")

	s.Nil(err)
	s.keyringMock.AssertExpectations(s.T())
}

func (s *TestSuite) TestSetWithinContextError() {
	s.keyringMock.On("Set", "aws-web-sso-helper", "myrole-AccessKeyId", "foobar").Return(errors.New("something went wrong"))

	err := s.credentials.SetWithinContext("MyRole", "AccessKeyId", "foobar")

	s.EqualError(err, "something went wrong")
	s.keyringMock.AssertExpectations(s.T())
}

func (s *TestSuite) TestSetWithinContextSuccess() {
	s.keyringMock.On("Set", "aws-web-sso-helper", "myrole-AccessKeyId", "foobar").Return(nil)

	err := s.credentials.SetWithinContext("MyRole", "AccessKeyId", "foobar")

	s.Nil(err)
	s.keyringMock.AssertExpectations(s.T())
}

func (s *TestSuite) TestSetExpiration() {
	s.keyringMock.On("Set", "aws-web-sso-helper", "myrole-Expiration", "2009-11-10T23:00:00Z").Return(nil)

	expiration := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
	err := s.credentials.SetExpiration("MyRole", &expiration)

	s.Nil(err)
	s.keyringMock.AssertExpectations(s.T())
}

func (s *TestSuite) TestDeleteAll() {
	s.keyringMock.On("Delete", "aws-web-sso-helper", "username").Return(nil)
	s.keyringMock.On("Delete", "aws-web-sso-helper", "password").Return(nil)

	s.credentials.DeleteAll()

	s.keyringMock.AssertExpectations(s.T())
}

func TestCredentials(t *testing.T) {
	suite.Run(t, new(TestSuite))
}
