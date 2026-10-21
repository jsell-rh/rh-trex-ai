// Package logger is the request-scoped logger used across trex.
//
// Every record goes through log/slog. The plug point is slog.SetDefault:
// a program that installs its own default logger (for example one that fans
// out to stdout and to an OpenTelemetry slog bridge) receives every record,
// together with the request context, so trace and span IDs stay reachable.
//
// When nothing has replaced the standard library's default logger, records
// go to the glog-style handler from NewGlogHandler, so the output is the
// same text trex has always printed.
package logger

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"sort"
	"time"

	"github.com/golang/glog"

	"github.com/openshift-online/rh-trex-ai/components/api-server/pkg/util"
)

type Logger interface {
	V(level int32) Logger
	Infof(format string, args ...interface{})
	Extra(key string, value interface{}) Logger
	Info(message string)
	Warning(message string)
	Error(message string)
	Fatal(message string)
}

var _ Logger = &logger{}

// Attribute keys emitted on every record that has the matching value.
const (
	opIDAttr      = "opid"
	accountIDAttr = "accountID"
	txIDAttr      = "tx_id"
)

// exit is replaced in tests so Fatal can be checked without ending the process.
var exit = os.Exit

type extra map[string]interface{}

type logger struct {
	context   context.Context
	level     int32
	accountID string
	username  string
	extra     extra
}

func NewLogger(ctx context.Context) Logger {
	if ctx == nil {
		ctx = context.Background()
	}
	logger := &logger{
		context:   ctx,
		level:     1,
		extra:     make(extra),
		accountID: util.GetAccountIDFromContext(ctx),
	}
	return logger
}

// V returns a copy of the logger at the given verbosity. The copy keeps the
// fields added with Extra.
func (l *logger) V(level int32) Logger {
	extras := make(extra, len(l.extra))
	for k, v := range l.extra {
		extras[k] = v
	}
	return &logger{
		context:   l.context,
		accountID: l.accountID,
		username:  l.username,
		level:     level,
		extra:     extras,
	}
}

// Extra adds a field to this logger and returns it, so calls can be chained.
func (l *logger) Extra(key string, value interface{}) Logger {
	l.extra[key] = value
	return l
}

func (l *logger) Infof(format string, args ...interface{}) {
	l.log(l.infoLevel(), styleFormat, format, args)
}

func (l *logger) Info(message string) {
	l.log(l.infoLevel(), styleLine, message, nil)
}

func (l *logger) Warning(message string) {
	l.log(slog.LevelWarn, styleLine, message, nil)
}

func (l *logger) Error(message string) {
	l.log(slog.LevelError, styleLine, message, nil)
}

// Fatal logs at Error level and then exits the process with status 1.
func (l *logger) Fatal(message string) {
	l.log(slog.LevelError, styleLine, message, nil)
	glog.Flush()
	exit(1)
}

// infoLevel maps glog verbosity to a slog level: V(0) and V(1) are Info,
// V(2) and above are Debug.
func (l *logger) infoLevel() slog.Level {
	if l.level >= 2 {
		return slog.LevelDebug
	}
	return slog.LevelInfo
}

// log builds one record and hands it to the handler with the request
// context. It calls the handler directly, instead of slog.Logger.Log, so the
// record's source points at the code that called the Logger rather than at
// this file. This is the wrapper pattern described in the log/slog docs.
func (l *logger) log(level slog.Level, style callStyle, format string, args []interface{}) {
	ctx := withCallInfo(l.context, callInfo{verbosity: l.verbosityFor(level), style: style})
	h := currentHandler()
	if !h.Enabled(ctx, level) {
		return
	}

	msg := format
	if args != nil {
		msg = fmt.Sprintf(format, args...)
	}

	var pcs [1]uintptr
	// Skip runtime.Callers, this function and the Logger method.
	runtime.Callers(3, pcs[:])
	r := slog.NewRecord(time.Now(), level, msg, pcs[0])
	r.AddAttrs(l.attrs()...)
	_ = h.Handle(ctx, r)
}

// verbosityFor returns the glog verbosity of an info or debug record. The
// default handler uses it to honor -v exactly as glog.V did.
func (l *logger) verbosityFor(level slog.Level) int32 {
	if level >= slog.LevelWarn {
		return 0
	}
	return l.level
}

func (l *logger) attrs() []slog.Attr {
	attrs := make([]slog.Attr, 0, 3+len(l.extra))
	if opid, ok := l.context.Value(OpIDKey).(string); ok {
		attrs = append(attrs, slog.String(opIDAttr, opid))
	}
	if l.accountID != "" {
		attrs = append(attrs, slog.String(accountIDAttr, l.accountID))
	}
	if txid, ok := l.context.Value("txid").(int64); ok {
		attrs = append(attrs, slog.Int64(txIDAttr, txid))
	}
	keys := make([]string, 0, len(l.extra))
	for k := range l.extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		attrs = append(attrs, slog.Any(k, l.extra[k]))
	}
	return attrs
}
