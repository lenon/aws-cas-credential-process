package web

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthorizationHeader(t *testing.T) {
	assert.Equal(t, authorizationHeader("alice", "pass"), "Basic YWxpY2U6cGFzcw==")
}
