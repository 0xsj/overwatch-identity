package redis

import (
	"github.com/0xsj/overwatch-pkg/security"
)

func parseSecurityDID(did string) (*security.DID, error) {
	return security.ParseDID(did)
}
