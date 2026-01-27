package grpc

import (
	pkggrpc "github.com/0xsj/overwatch-pkg/grpc"
)

// toGRPCError converts domain errors to gRPC status errors.
// Since domain errors use pkg/errors with Kind, the pkg/grpc
// error mapping handles the conversion automatically.
func toGRPCError(err error) error {
	if err == nil {
		return nil
	}
	return pkggrpc.ToStatus(err).Err()
}
