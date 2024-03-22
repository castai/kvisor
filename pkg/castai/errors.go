package castai

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func IsGRPCError(err error, codes ...codes.Code) bool {
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	for _, code := range codes {
		if st.Code() == code {
			return true
		}
	}
	return false
}
