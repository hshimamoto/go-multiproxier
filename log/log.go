// go-multiproxier/log
//
// MIT License Copyright(c) 2018 Hiroshi Shimamoto
// vim:set sw=4 sts=4:
//

package log

import (
    "io"
    "log"
    "os"
    "strings"
    "sync"
)

var logger *log.Logger = log.New(os.Stderr, "", log.LstdFlags)

func Fatal(v ...interface{}) {
    logger.Fatal(v...)
}

func Println(v ...interface{}) {
    logger.Println(v...)
}

func Printf(fmt string, v ...interface{}) {
    logger.Printf(fmt, v...)
}

func Init(w io.Writer) {
    logger = log.New(w, "", log.LstdFlags)
}

// local log array
type LocalLog struct {
    logs []string
    idx, capa int
    logger *log.Logger
    m *sync.Mutex
}

func (l *LocalLog)Write(p []byte) (int, error) {
    l.m.Lock()
    l.logs[l.idx] = strings.TrimSpace(string(p))
    l.idx++
    if l.idx >= l.capa {
	l.idx = 0
    }
    l.m.Unlock()
    return len(p), nil
}

func (l *LocalLog)Printf(fmt string, v ...interface{}) {
    l.logger.Printf(fmt, v...)
}

func (l *LocalLog)Get() []string {
    logs := []string{}
    l.m.Lock()
    for i := 0; i < l.capa; i++ {
	idx := l.idx + i
	if idx >= l.capa {
	    idx -= l.capa
	}
	s := l.logs[idx]
	if s != "" {
	    logs = append(logs, s)
	}
    }
    l.m.Unlock()
    return logs
}

func NewLocalLog(capa int) *LocalLog {
    l := &LocalLog{
	logs: make([]string, capa),
	idx: 0,
	capa: capa,
	m: &sync.Mutex{},
    }
    l.logger = log.New(l, "", log.LstdFlags)
    return l
}
