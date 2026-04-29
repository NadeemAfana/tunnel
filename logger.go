package main

import (
	"fmt"
	"io"
	stdlog "log"
	"os"
	"strings"
)

// Tiny printf-style leveled logger built on the standard library, replacing
// logrus while preserving the existing call-site shape (`log.Printf`,
// `log.Debugf`, `log.Fatalf`, etc.).

type logLevel int

const (
	levelDebug logLevel = iota
	levelInfo
	levelWarn
	levelError
)

func levelTag(l logLevel) string {
	switch l {
	case levelDebug:
		return "DEBUG"
	case levelInfo:
		return "INFO "
	case levelWarn:
		return "WARN "
	case levelError:
		return "ERROR"
	}
	return "?????"
}

type leveledLogger struct {
	base  *stdlog.Logger
	level logLevel
}

// log is referenced by the rest of the package the same way the old logrus
// alias was. Defaults match logrus: stderr output, info level.
var log = &leveledLogger{
	base:  stdlog.New(os.Stderr, "", stdlog.LstdFlags),
	level: levelInfo,
}

func (l *leveledLogger) SetOutput(w io.Writer) { l.base.SetOutput(w) }
func (l *leveledLogger) SetLevel(lvl logLevel) { l.level = lvl }

func (l *leveledLogger) emit(threshold logLevel, msg string) {
	if threshold < l.level {
		return
	}
	_ = l.base.Output(3, "["+levelTag(threshold)+"] "+msg)
}

func (l *leveledLogger) Printf(format string, args ...any) {
	l.emit(levelInfo, fmt.Sprintf(format, args...))
}
func (l *leveledLogger) Println(args ...any) {
	l.emit(levelInfo, fmt.Sprintln(args...))
}

func (l *leveledLogger) Debugf(format string, args ...any) {
	l.emit(levelDebug, fmt.Sprintf(format, args...))
}
func (l *leveledLogger) Infof(format string, args ...any) {
	l.emit(levelInfo, fmt.Sprintf(format, args...))
}
func (l *leveledLogger) Infoln(args ...any) {
	l.emit(levelInfo, fmt.Sprintln(args...))
}
func (l *leveledLogger) Warnf(format string, args ...any) {
	l.emit(levelWarn, fmt.Sprintf(format, args...))
}

func (l *leveledLogger) Fatal(args ...any) {
	l.emit(levelError, fmt.Sprint(args...))
	os.Exit(1)
}
func (l *leveledLogger) Fatalf(format string, args ...any) {
	l.emit(levelError, fmt.Sprintf(format, args...))
	os.Exit(1)
}
func (l *leveledLogger) Fatalln(args ...any) {
	l.emit(levelError, fmt.Sprintln(args...))
	os.Exit(1)
}

func (l *leveledLogger) ParseLevel(s string) (logLevel, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return levelDebug, nil
	case "info":
		return levelInfo, nil
	case "warn", "warning":
		return levelWarn, nil
	case "error":
		return levelError, nil
	}
	return levelInfo, fmt.Errorf("unknown log level %q", s)
}
