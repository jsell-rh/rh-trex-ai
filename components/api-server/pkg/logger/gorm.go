package logger

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"time"

	gormlogger "gorm.io/gorm/logger"
)

// NewGormLogger returns a GORM logger that writes through slog, with the
// statement's context, so SQL logs carry the request's trace and span. It
// writes no color codes. Its defaults match GORM's own default logger: Warn
// level, and queries slower than 200ms are reported as slow.
func NewGormLogger() gormlogger.Interface {
	return &gormLogger{
		level:         gormlogger.Warn,
		slowThreshold: 200 * time.Millisecond,
	}
}

type gormLogger struct {
	level         gormlogger.LogLevel
	slowThreshold time.Duration
}

var _ gormlogger.Interface = &gormLogger{}

func (g *gormLogger) LogMode(level gormlogger.LogLevel) gormlogger.Interface {
	ng := *g
	ng.level = level
	return &ng
}

func (g *gormLogger) Info(ctx context.Context, msg string, data ...interface{}) {
	if g.level >= gormlogger.Info {
		g.emit(ctx, slog.LevelInfo, fmt.Sprintf(msg, data...))
	}
}

func (g *gormLogger) Warn(ctx context.Context, msg string, data ...interface{}) {
	if g.level >= gormlogger.Warn {
		g.emit(ctx, slog.LevelWarn, fmt.Sprintf(msg, data...))
	}
}

func (g *gormLogger) Error(ctx context.Context, msg string, data ...interface{}) {
	if g.level >= gormlogger.Error {
		g.emit(ctx, slog.LevelError, fmt.Sprintf(msg, data...))
	}
}

// Trace reports one SQL statement. Errors log at Error, slow statements at
// Warn, and every statement at Info when the level is Info (GORM's Debug()).
func (g *gormLogger) Trace(ctx context.Context, begin time.Time, fc func() (sql string, rowsAffected int64), err error) {
	if g.level <= gormlogger.Silent {
		return
	}
	elapsed := time.Since(begin)
	switch {
	case err != nil && g.level >= gormlogger.Error:
		sql, rows := fc()
		g.emit(ctx, slog.LevelError, "sql error", sqlAttrs(elapsed, rows, sql, slog.String("error", err.Error()))...)
	case g.slowThreshold != 0 && elapsed > g.slowThreshold && g.level >= gormlogger.Warn:
		sql, rows := fc()
		g.emit(ctx, slog.LevelWarn, "slow sql", sqlAttrs(elapsed, rows, sql,
			slog.String("threshold", g.slowThreshold.String()))...)
	case g.level >= gormlogger.Info:
		sql, rows := fc()
		g.emit(ctx, slog.LevelInfo, "sql", sqlAttrs(elapsed, rows, sql)...)
	}
}

// ParamsFilter keeps bound values in the SQL text, as GORM's default logger
// does unless ParameterizedQueries is set.
func (g *gormLogger) ParamsFilter(_ context.Context, sql string, params ...interface{}) (string, []interface{}) {
	return sql, params
}

// sqlAttrs puts the statement last, so it reads well in the text output.
func sqlAttrs(elapsed time.Duration, rows int64, sql string, extra ...slog.Attr) []slog.Attr {
	attrs := append([]slog.Attr{}, extra...)
	attrs = append(attrs,
		slog.String("elapsed", fmt.Sprintf("%.3fms", float64(elapsed.Nanoseconds())/1e6)),
	)
	if rows >= 0 {
		attrs = append(attrs, slog.Int64("rows", rows))
	}
	return append(attrs, slog.String("sql", sql))
}

func (g *gormLogger) emit(ctx context.Context, level slog.Level, msg string, attrs ...slog.Attr) {
	if ctx == nil {
		ctx = context.Background()
	}
	h := currentHandler()
	if !h.Enabled(ctx, level) {
		return
	}
	r := slog.NewRecord(time.Now(), level, msg, callerOutsideGorm())
	r.AddAttrs(attrs...)
	_ = h.Handle(ctx, r)
}

// callerOutsideGorm returns the program counter of the first frame outside
// GORM and this file, which is the code that ran the query.
func callerOutsideGorm() uintptr {
	var pcs [32]uintptr
	n := runtime.Callers(3, pcs[:])
	for _, pc := range pcs[:n] {
		f, _ := runtime.CallersFrames([]uintptr{pc}).Next()
		if strings.Contains(f.File, "gorm.io/") || strings.HasSuffix(f.File, "pkg/logger/gorm.go") {
			continue
		}
		return pc
	}
	return 0
}
