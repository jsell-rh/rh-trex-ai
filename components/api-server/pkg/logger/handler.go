// Package logger sets up log/slog for trex.
//
// trex logs only through log/slog, always with the request context when one
// is in scope (slog.InfoContext and friends). The plug point is
// slog.SetDefault: a program that installs its own default logger, for
// example one that fans out to stdout and to an OpenTelemetry slog bridge,
// receives every trex record together with its context.
//
// To keep the request attributes (opid, accountID, tx_id) on records sent to
// a custom handler, wrap that handler with WithContextAttrs.
package logger

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"sync"

	"github.com/openshift-online/rh-trex-ai/components/api-server/pkg/util"
)

// Attribute keys that WithContextAttrs adds from the context.
const (
	OpIDAttr      = "opid"
	AccountIDAttr = "accountID"
	TxIDAttr      = "tx_id"
)

// Output formats accepted by NewHandler.
const (
	FormatText = "text"
	FormatJSON = "json"
)

// NewHandler returns slog's text or JSON handler writing to w at the given
// level. format must be FormatText or FormatJSON.
func NewHandler(w io.Writer, format string, level slog.Leveler) (slog.Handler, error) {
	opts := &slog.HandlerOptions{Level: level}
	switch format {
	case FormatText, "":
		return slog.NewTextHandler(w, opts), nil
	case FormatJSON:
		return slog.NewJSONHandler(w, opts), nil
	default:
		return nil, fmt.Errorf("unknown log format %q: use %q or %q", format, FormatText, FormatJSON)
	}
}

// WithContextAttrs wraps h so every record also carries the request
// attributes found in the context passed to the handler: opid (from
// OperationIDMiddleware or WithOpID), accountID and tx_id. Records logged
// without a context, or with a context that has none of these, are passed
// through unchanged.
//
// The attributes are added when the record is handled, so after WithGroup
// they land inside that group.
func WithContextAttrs(h slog.Handler) slog.Handler {
	return &contextHandler{next: h}
}

type contextHandler struct {
	next slog.Handler
}

func (h *contextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *contextHandler) Handle(ctx context.Context, r slog.Record) error {
	if attrs := contextAttrs(ctx); len(attrs) > 0 {
		// Clone so the caller's record is not changed.
		r = r.Clone()
		r.AddAttrs(attrs...)
	}
	return h.next.Handle(ctx, r)
}

func (h *contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &contextHandler{next: h.next.WithAttrs(attrs)}
}

func (h *contextHandler) WithGroup(name string) slog.Handler {
	return &contextHandler{next: h.next.WithGroup(name)}
}

func contextAttrs(ctx context.Context) []slog.Attr {
	if ctx == nil {
		return nil
	}
	var attrs []slog.Attr
	if opid, ok := ctx.Value(OpIDKey).(string); ok && opid != "" {
		attrs = append(attrs, slog.String(OpIDAttr, opid))
	}
	if account := util.GetAccountIDFromContext(ctx); account != "" {
		attrs = append(attrs, slog.String(AccountIDAttr, account))
	}
	if txid, ok := ctx.Value("txid").(int64); ok {
		attrs = append(attrs, slog.Int64(TxIDAttr, txid))
	}
	return attrs
}

var (
	mu sync.Mutex
	// stdDefault is the standard library's default logger, captured when
	// this package is initialized.
	stdDefault = slog.Default()
	// installed is the last logger SetDefaultIfUnset installed.
	installed *slog.Logger
)

// SetDefaultIfUnset makes h the slog default, unless the program has set its
// own default. It reports whether it installed h. trex calls it at startup,
// so a program that called slog.SetDefault earlier keeps its handler, and one
// that calls it later replaces trex's.
//
// Detection: this package keeps the *slog.Logger that slog.Default returned
// when the package was initialized, and the one it installed itself.
// slog.SetDefault always stores a new pointer, so any other value means the
// program set its own default.
//
// slog.SetDefault also sends the standard "log" package through the new
// handler. This function puts the log package's output and flags back, so
// log.Printf output does not change.
func SetDefaultIfUnset(h slog.Handler) bool {
	mu.Lock()
	defer mu.Unlock()
	current := slog.Default()
	if current != stdDefault && current != installed {
		return false
	}
	w, flags := log.Writer(), log.Flags()
	l := slog.New(h)
	slog.SetDefault(l)
	log.SetOutput(w)
	log.SetFlags(flags)
	installed = l
	return true
}
