package keyring

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type backendMock struct {
	mock.Mock
}

func (m *backendMock) Get(service, key string) (string, error) {
	args := m.Called(service, key)
	return args.String(0), args.Error(1)
}

func (m *backendMock) Set(service, key, value string) error {
	args := m.Called(service, key, value)
	return args.Error(0)
}

func (m *backendMock) Delete(service, key string) error {
	args := m.Called(service, key)
	return args.Error(0)
}

type TestSuite struct {
	suite.Suite

	backendMock *backendMock
	keyring     *Keyring
}

func (s *TestSuite) SetupTest() {
	s.backendMock = new(backendMock)
	s.keyring = &Keyring{backend: s.backendMock}
}

func (s *TestSuite) TestGetError() {
	s.backendMock.On("Get", "aws-cas-credential-process", "username").Return("", errors.New("something went wrong"))

	username, err := s.keyring.Get("username")

	s.Empty(username)
	s.EqualError(err, "key not found: username")
	s.backendMock.AssertExpectations(s.T())
}

func (s *TestSuite) TestGetWithSuccess() {
	s.backendMock.On("Get", "aws-cas-credential-process", "username").Return("alice", nil)

	username, err := s.keyring.Get("username")

	s.Equal(username, "alice")
	s.Nil(err)
	s.backendMock.AssertExpectations(s.T())
}

func (s *TestSuite) TestGetWithinContextError() {
	s.backendMock.On("Get", "aws-cas-credential-process", "myrole-AccessKeyId").Return("", errors.New("something went wrong"))

	value, err := s.keyring.GetWithinContext("MyRole", "AccessKeyId")

	s.Empty(value)
	s.EqualError(err, "key not found: myrole-AccessKeyId")
	s.backendMock.AssertExpectations(s.T())
}

func (s *TestSuite) TestGetWithinContextWithSuccess() {
	s.backendMock.On("Get", "aws-cas-credential-process", "myrole-AccessKeyId").Return("foobarbaz", nil)

	value, err := s.keyring.GetWithinContext("MyRole", "AccessKeyId")

	s.Equal(value, "foobarbaz")
	s.Nil(err)
	s.backendMock.AssertExpectations(s.T())
}

func (s *TestSuite) TestGetExpiration() {
	s.backendMock.On("Get", "aws-cas-credential-process", "myrole-Expiration").Return("2009-11-10T23:00:00Z", nil)

	value, err := s.keyring.GetExpiration("MyRole")
	expected := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)

	s.Equal(value, &expected)
	s.Nil(err)
	s.backendMock.AssertExpectations(s.T())
}

func (s *TestSuite) TestSetError() {
	s.backendMock.On("Set", "aws-cas-credential-process", "username", "alice").Return(errors.New("something went wrong"))

	err := s.keyring.Set("username", "alice")

	s.EqualError(err, "something went wrong")
	s.backendMock.AssertExpectations(s.T())
}

func (s *TestSuite) TestSetSuccess() {
	s.backendMock.On("Set", "aws-cas-credential-process", "username", "alice").Return(nil)

	err := s.keyring.Set("username", "alice")

	s.Nil(err)
	s.backendMock.AssertExpectations(s.T())
}

func (s *TestSuite) TestSetWithinContextError() {
	s.backendMock.On("Set", "aws-cas-credential-process", "myrole-AccessKeyId", "foobar").Return(errors.New("something went wrong"))

	err := s.keyring.SetWithinContext("MyRole", "AccessKeyId", "foobar")

	s.EqualError(err, "something went wrong")
	s.backendMock.AssertExpectations(s.T())
}

func (s *TestSuite) TestSetWithinContextSuccess() {
	s.backendMock.On("Set", "aws-cas-credential-process", "myrole-AccessKeyId", "foobar").Return(nil)

	err := s.keyring.SetWithinContext("MyRole", "AccessKeyId", "foobar")

	s.Nil(err)
	s.backendMock.AssertExpectations(s.T())
}

func (s *TestSuite) TestSetExpiration() {
	s.backendMock.On("Set", "aws-cas-credential-process", "myrole-Expiration", "2009-11-10T23:00:00Z").Return(nil)

	expiration := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
	err := s.keyring.SetExpiration("MyRole", &expiration)

	s.Nil(err)
	s.backendMock.AssertExpectations(s.T())
}

func (s *TestSuite) TestDeleteAll() {
	s.backendMock.On("Delete", "aws-cas-credential-process", "username").Return(nil)
	s.backendMock.On("Delete", "aws-cas-credential-process", "password").Return(nil)

	s.keyring.DeleteAll()

	s.backendMock.AssertExpectations(s.T())
}

func TestKeyring(t *testing.T) {
	suite.Run(t, new(TestSuite))
}
