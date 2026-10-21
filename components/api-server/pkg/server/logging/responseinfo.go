package logging

import (
	"context"
	"net/http"
)

type ResponseInfo struct {
	Header  http.Header `json:"response_header,omitempty"`
	Body    []byte      `json:"response_body,omitempty"`
	Status  int         `json:"response_status,omitempty"`
	Elapsed string      `json:"elapsed,omitempty"`

	// ctx is the request context, used to decide whether debug details
	// are logged for this response.
	ctx context.Context
}
