package logger

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"runtime"
	"strings"

	"github.com/golang/glog"
)

// callStyle records which Logger method produced a record, so the default
// handler can print exactly the text the glog-backed logger printed.
type callStyle int

const (
	// styleFormat is Infof and any record that does not come from Logger:
	// "[opid=..] message".
	styleFormat callStyle = iota
	// styleLine is Info, Warning, Error and Fatal: "[opid=..]  message extras".
	styleLine
)

// callInfo travels in the context passed to the handler. Other handlers
// ignore it. It carries the glog verbosity, which a slog level cannot hold.
type callInfo struct {
	verbosity int32
	style     callStyle
}

type callInfoKey struct{}

func withCallInfo(ctx context.Context, ci callInfo) context.Context {
	return context.WithValue(ctx, callInfoKey{}, ci)
}

// stdDefault is the standard library's default logger, captured when this
// package is initialized. If slog.Default still returns it, no program code
// has called slog.SetDefault.
var stdDefault = slog.Default()

var defaultGlogHandler = NewGlogHandler()

// currentHandler returns the handler for Logger records. It is the handler of
// slog.Default, unless nobody has called slog.SetDefault yet. In that case it
// is the glog handler, so libraries and tests that never run pkg/cmd keep the
// output they always had.
func currentHandler() slog.Handler {
	d := slog.Default()
	if d == stdDefault {
		return defaultGlogHandler
	}
	return d.Handler()
}

// SetDefaultIfUnset installs the glog handler as the slog default, unless
// the program already called slog.SetDefault. It reports whether it
// installed the handler.
//
// Detection: this package keeps the *slog.Logger that slog.Default returned
// when the package was initialized. slog.SetDefault always stores a new
// pointer, so a different pointer means the program set its own default.
//
// slog.SetDefault also sends the standard "log" package through the new
// handler. This function puts the log package's previous output and flags
// back, so log.Printf output does not change.
func SetDefaultIfUnset() bool {
	if slog.Default() != stdDefault {
		return false
	}
	w, flags := log.Writer(), log.Flags()
	slog.SetDefault(slog.New(defaultGlogHandler))
	log.SetOutput(w)
	log.SetFlags(flags)
	return true
}

// NewGlogHandler returns a slog.Handler that writes through glog, in the
// format trex has always used:
//
//	I1021 08:25:17.913474 1 file.go:97] [opid=3Kzr...] gRPC /x.y/Z OK 29ms
//
// The opid, accountID and tx_id attributes become the bracketed prefix. Other
// attributes are appended as key=value. Records honor glog's -v, -vmodule,
// -logtostderr and the other glog flags. Info records from Logger.V(n) print
// only when glog.V(n) is on. Other Debug records need -v=2 or more.
//
// A program that sets its own slog default can use this handler as the
// stdout leg of a fan-out handler.
func NewGlogHandler() slog.Handler {
	return &glogHandler{}
}

type glogHandler struct {
	attrs  []slog.Attr
	prefix string // group prefix for attributes added later, such as "db."
}

func (h *glogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	v := verbosity(ctx, level)
	if v <= 0 {
		return true
	}
	return bool(glog.V(glog.Level(v))) || vmoduleSet()
}

func (h *glogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	nh := &glogHandler{prefix: h.prefix, attrs: append([]slog.Attr{}, h.attrs...)}
	for _, a := range attrs {
		nh.attrs = append(nh.attrs, qualify(h.prefix, a))
	}
	return nh
}

func (h *glogHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &glogHandler{attrs: h.attrs, prefix: h.prefix + name + "."}
}

func (h *glogHandler) Handle(ctx context.Context, r slog.Record) error {
	// Find the caller's frame, so glog prints its file and line rather than
	// this file. depth counts frames above this function, which is what the
	// glog *Depth functions expect.
	var pcs [64]uintptr
	n := runtime.Callers(1, pcs[:])
	depth := 0
	for i := 0; i < n; i++ {
		if pcs[i] == r.PC {
			depth = i
			break
		}
	}

	v := verbosity(ctx, r.Level)
	if v > 0 && !glog.VDepth(depth, glog.Level(v)) {
		return nil
	}

	text := h.format(ctx, r)
	switch {
	case r.Level >= slog.LevelError:
		glog.ErrorDepth(depth, text)
	case r.Level >= slog.LevelWarn:
		glog.WarningDepth(depth, text)
	case v > 0:
		// Same path as glog.V(v).Info, which marks the entry as verbose.
		glog.Verbose(true).InfoDepth(depth, text)
	default:
		glog.InfoDepth(depth, text)
	}
	return nil
}

// format renders the record as the glog-backed logger did.
func (h *glogHandler) format(ctx context.Context, r slog.Record) string {
	var opid, account, tx string
	var extras []string
	add := func(a slog.Attr) {
		switch a.Key {
		case opIDAttr:
			opid = a.Value.String()
		case accountIDAttr:
			account = a.Value.String()
		case txIDAttr:
			tx = a.Value.String()
		default:
			extras = appendAttr(extras, "", a)
		}
	}
	for _, a := range h.attrs {
		add(a)
	}
	r.Attrs(func(a slog.Attr) bool {
		add(qualify(h.prefix, a))
		return true
	})

	var b strings.Builder
	if opid != "" {
		fmt.Fprintf(&b, "[opid=%s]", opid)
	}
	if account != "" {
		fmt.Fprintf(&b, "[accountID=%s]", account)
	}
	if tx != "" {
		fmt.Fprintf(&b, "[tx_id=%s]", tx)
	}
	b.WriteString(" ")
	prefix := b.String()

	ci, fromLogger := ctx.Value(callInfoKey{}).(callInfo)
	if fromLogger {
		if ci.style == styleLine {
			return fmt.Sprintf("%s %s %s", prefix, r.Message, strings.Join(extras, " "))
		}
		// Logger.Infof never printed Extra fields. Structured handlers
		// still receive them as attributes.
		return prefix + r.Message
	}
	if opid == "" && account == "" && tx == "" {
		// Records from slog itself print the message without a leading space.
		prefix = ""
	}
	if len(extras) == 0 {
		return prefix + r.Message
	}
	return prefix + r.Message + " " + strings.Join(extras, " ")
}

// qualify adds a group prefix to an attribute key. Known keys stay
// recognizable only at the top level.
func qualify(prefix string, a slog.Attr) slog.Attr {
	if prefix == "" || a.Key == "" {
		return a
	}
	return slog.Attr{Key: prefix + a.Key, Value: a.Value}
}

// appendAttr renders a as key=value, flattening groups into dotted keys.
func appendAttr(out []string, prefix string, a slog.Attr) []string {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return out
	}
	if a.Value.Kind() == slog.KindGroup {
		p := prefix
		if a.Key != "" {
			p = prefix + a.Key + "."
		}
		for _, ga := range a.Value.Group() {
			out = appendAttr(out, p, ga)
		}
		return out
	}
	return append(out, fmt.Sprintf("%s%s=%v", prefix, a.Key, a.Value.Any()))
}

// verbosity is the glog -v level a record needs. Records from Logger carry
// it in the context. Other records map from the slog level: Info and above
// need none, Debug needs 2, and each step below Debug needs one more.
func verbosity(ctx context.Context, level slog.Level) int32 {
	if level >= slog.LevelWarn {
		return 0
	}
	if ci, ok := ctx.Value(callInfoKey{}).(callInfo); ok {
		return ci.verbosity
	}
	switch {
	case level >= slog.LevelInfo:
		return 0
	case level > slog.LevelDebug:
		return 1
	default:
		return 2 + int32(slog.LevelDebug-level)
	}
}

// vmoduleSet reports whether -vmodule is in use. When it is, Enabled cannot
// decide without the caller's file, so Handle makes the final check.
func vmoduleSet() bool {
	f := flag.Lookup("vmodule")
	return f != nil && f.Value.String() != ""
}
