package main

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	log2 "github.com/Entscheider/sshtool/logger"
)

// Logger is interface for basic logging methods
type Logger interface {
	io.Closer
	// Warn prints a warning msg under the given tag
	Warn(tag string, msg string)
	// Err prints an error under the given tag
	Err(tag string, msg string)
	// Debug prints a debug output under the given tag
	Debug(tag string, msg string)
	// Info prints a info output under the given tag
	Info(tag string, msg string)
}

// A default implementation of a logger that avoids parallel printing in different thread
type stdLogger struct {
	channel     chan<- string
	waitChannel <-chan bool
	wg          *sync.WaitGroup
}

// NewLogger creates a new Logger implementation that writes all outputs to the given writer
func NewLogger(writer io.Writer) Logger {
	c := make(chan string)
	wc := make(chan bool)
	wg := sync.WaitGroup{}
	go func() {
		defer wg.Done()
		defer close(wc)
		wg.Add(1)
		if closer, ok := writer.(io.WriteCloser); ok {
			defer closer.Close()
		}
		for text := range c {
			_, _ = fmt.Fprint(writer, text)
			wc <- true
		}
	}()
	return &stdLogger{c, wc, &wg}
}

func (l *stdLogger) Close() error {
	close(l.channel)
	l.wg.Wait()
	return nil
}

func (l *stdLogger) print(symbol string, tag string, msg string) {
	t := time.Now()
	l.channel <- fmt.Sprintf("%s [%s] %s - %s\n", t.Local(), symbol, tag, msg)
	<-l.waitChannel
}

func (l *stdLogger) Warn(tag string, msg string) {
	l.print("W", tag, msg)
}

func (l *stdLogger) Err(tag string, msg string) {
	l.print("E", tag, msg)
}

func (l *stdLogger) Debug(tag string, msg string) {
	l.print("D", tag, msg)
}

func (l *stdLogger) Info(tag string, msg string) {
	l.print("I", tag, msg)
}

// AccessLogger that prints all output to an io.Writer and prevents multiple writes from different threads.
type stdAccessLogger struct {
	channel     chan<- string
	waitChannel <-chan bool
	wg          *sync.WaitGroup
	fileCb      func(string)
}

// NewAccessLogger creates a new standard AccessLogger that prints all output to the given writer
func NewAccessLogger(writer io.Writer, fileCb func(string)) log2.AccessLogger {
	c := make(chan string)
	wc := make(chan bool)
	wg := sync.WaitGroup{}
	go func() {
		defer wg.Done()
		defer close(wc)
		wg.Add(1)
		if closer, ok := writer.(io.WriteCloser); ok {
			defer closer.Close()
		}
		for text := range c {
			_, _ = fmt.Fprintf(writer, "%s\n", text)
			wc <- true
		}
	}()
	return &stdAccessLogger{c, wc, &wg, fileCb}
}

// Collects information about an access log entry
type entry struct {
	logType        string
	connectionInfo log2.ConnectionInfo
	path           string
	kind           string
	status         string
}

func (l *stdAccessLogger) printStrings(entries ...string) {
	t := time.Now()
	values := make([]string, len(entries)+1)
	values[0] = fmt.Sprintf("\"%s\"", t.Local())
	for i, e := range entries {
		values[i+1] = fmt.Sprintf("\"%s\"", strings.ReplaceAll(e, "\"", "\"\""))
	}
	l.channel <- strings.Join(values, ",")
	<-l.waitChannel
}

func (l *stdAccessLogger) printEntry(e entry) {
	l.printStrings(e.logType, e.connectionInfo.IP, e.connectionInfo.Username,
		e.path, e.kind, e.status)
}

func (l *stdAccessLogger) NewLogin(connection log2.ConnectionInfo, status string) {
	l.printEntry(entry{
		logType:        "login",
		connectionInfo: connection,
		status:         status,
	})
}

func (l *stdAccessLogger) Logout(connection log2.ConnectionInfo) {
	l.printEntry(entry{
		logType:        "logout",
		connectionInfo: log2.ConnectionInfo(connection),
	})
}

func (l *stdAccessLogger) NewAccess(connection log2.ConnectionInfo, path string, kind string, status string) {
	l.printEntry(entry{
		logType:        "access",
		connectionInfo: connection,
		path:           path,
		kind:           kind,
		status:         status,
	})
}

func (l *stdAccessLogger) Close() error {
	close(l.channel)
	l.wg.Wait()
	return nil
}
