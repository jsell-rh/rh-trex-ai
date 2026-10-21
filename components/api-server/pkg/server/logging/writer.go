package logging

import (
	"log/slog"
	"net/http"
)

func NewLoggingWriter(w http.ResponseWriter, r *http.Request, f LogFormatter) *LoggingWriter {
	return &LoggingWriter{ResponseWriter: w, request: r, formatter: f}
}

type LoggingWriter struct {
	http.ResponseWriter
	request        *http.Request
	formatter      LogFormatter
	responseStatus int
	responseBody   []byte
}

func (writer *LoggingWriter) Write(body []byte) (int, error) {
	writer.responseBody = body
	return writer.ResponseWriter.Write(body)
}

func (writer *LoggingWriter) WriteHeader(status int) {
	writer.responseStatus = status
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *LoggingWriter) log(msg string, details string, err error) {
	ctx := writer.request.Context()
	switch err {
	case nil:
		slog.InfoContext(ctx, msg, "details", details)
	default:
		slog.ErrorContext(ctx, "Unable to format request/response for log", "error", err)
	}
}

func (writer *LoggingWriter) prepareRequestLog() (string, error) {
	return writer.formatter.FormatRequestLog(writer.request)
}

func (writer *LoggingWriter) prepareResponseLog(elapsed string) (string, error) {
	info := &ResponseInfo{
		Header:  writer.Header(),
		Body:    writer.responseBody,
		Status:  writer.responseStatus,
		Elapsed: elapsed,
	}

	return writer.formatter.FormatResponseLog(info)
}
