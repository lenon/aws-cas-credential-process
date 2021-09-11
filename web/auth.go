package web

import (
	"encoding/base64"
	"fmt"
)

func authorizationHeader(username string, password string) string {
	credentials := fmt.Sprintf("%s:%s", username, password)
	base64auth := base64.StdEncoding.EncodeToString([]byte(credentials))

	return fmt.Sprintf("Basic %s", base64auth)
}
