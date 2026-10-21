package auth

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/openshift-online/rh-trex-ai/components/api-server/pkg/errors"
	"github.com/openshift-online/rh-trex-ai/components/api-server/pkg/logger"
)

func handleError(ctx context.Context, w http.ResponseWriter, code errors.ServiceErrorCode, reason string) {
	operationID := logger.GetOperationID(ctx)
	err := errors.New(code, "%s", reason)
	if err.HttpCode >= 400 && err.HttpCode <= 499 {
		slog.InfoContext(ctx, "Auth request rejected", "error", err)
	} else {
		slog.ErrorContext(ctx, "Auth request failed", "error", err)
	}

	writeJSONResponse(w, err.HttpCode, err.AsOpenapiError(operationID))
}

func writeJSONResponse(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	if payload != nil {
		response, _ := json.Marshal(payload)
		_, _ = w.Write(response)
	}
}
