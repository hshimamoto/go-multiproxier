// go-multiproxier/outproxy
//
// MIT License Copyright(c) 2018 Hiroshi Shimamoto
// vim:set sw=4 sts=4:
//

package outproxy

import (
    "fmt"
    "log"
    "net"
    "time"
)

type OutProxy struct {
    Addr string
    Bad time.Time
    Timeout time.Duration
    NumRunning int
    // stats
    Success, Fail int
}

func (outproxy *OutProxy)Line() string {
    st := "o"
    if outproxy.Bad.After(time.Now()) {
	st = "x"
    }
    name := outproxy.Addr
    succ := outproxy.Success
    fail := outproxy.Fail
    to := outproxy.Timeout
    return fmt.Sprintf("%s %s %d %d to:%v\n", st, name, succ, fail, to)
}

func (outproxy *OutProxy)CheckConnect(conn net.Conn, label string) ([]byte, error) {
    buf := make([]byte, 256)
    conn.SetReadDeadline(time.Now().Add(outproxy.Timeout))
    n, err := conn.Read(buf)
    if err != nil {
	e, ok := err.(net.Error)
	if ok && e.Timeout() {
	    max := 30 * time.Second
	    t := outproxy.Timeout + 5 * time.Second
	    if t > max {
		t = max
	    }
	    if outproxy.Timeout != t {
		log.Printf("OutProxy %s timeout change to %v\n", outproxy.Addr, t)
		outproxy.Timeout = t
	    }
	}
	return nil, fmt.Errorf("%s: waiting CONNECT resp from %s: %s", label, outproxy.Addr, err.Error())
    }
    if n == 0 {
	return nil, fmt.Errorf("%s: remote connection to %s closed", label, outproxy.Addr)
    }
    conn.SetReadDeadline(time.Now().Add(24 * time.Hour)) // 1day
    return buf[:n], err
}
