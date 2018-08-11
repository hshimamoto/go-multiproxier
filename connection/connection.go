// go-multiproxier/conn
//
// MIT License Copyright(c) 2018 Hiroshi Shimamoto
// vim:set sw=4 sts=4:
//

package connection

import (
    "fmt"
    "io"
    "log"
    "net"
    "net/http"
    "strings"
    "time"

    "github.com/hshimamoto/go-multiproxier/outproxy"
)

func Transfer(lconn, rconn net.Conn) {
    d1 := make(chan bool)
    d2 := make(chan bool)
    go func() {
	io.Copy(rconn, lconn)
	d1 <- true
    }()
    go func() {
	io.Copy(lconn, rconn)
	d2 <- true
    }()
    select {
    case <-d1: go func() { <-d2 }()
    case <-d2: go func() { <-d1 }()
    }
    time.Sleep(time.Second)
}

var timeout time.Duration = 10 * time.Second

func CheckConnectOK(resp string) error {
    lines := strings.Split(resp, "\r\n")
    codes := strings.Split(lines[0], " ")
    if codes[1] != "200" {
	return fmt.Errorf(lines[0])
    }
    return nil
}

func OpenProxy(proxy, outproxy string) (net.Conn, error, bool) {
    conn, err := net.DialTimeout("tcp", proxy, timeout)
    if err != nil {
	return nil, err, false
    }
    msg := "CONNECT " + outproxy + " HTTP/1.0\r\n\r\n"
    conn.Write([]byte(msg))
    buf := make([]byte, 256) // just for 200 OK
    conn.SetReadDeadline(time.Now().Add(timeout))
    n, err := conn.Read(buf) // expect 200 OK
    if err != nil || n == 0 {
	conn.Close()
	if err != nil {
	    log.Println("proxy Read fail:", err)
	} else {
	    log.Println("proxy closed")
	}
	return nil, fmt.Errorf("READ NG"), true
    }
    err = CheckConnectOK(string(buf[:n]))
    if err != nil {
	conn.Close()
	return nil, fmt.Errorf("CONNECT NG: %v", err), true
    }
    return conn, nil, false
}

type Connection struct {
    domain string
    r *http.Request
    w http.ResponseWriter
    Proc ConnectionProc
    outproxy *outproxy.OutProxy
}

func New(domain string, r *http.Request, w http.ResponseWriter, proc ConnectionProc) *Connection {
    c := &Connection{ domain: domain, r: r, w: w, Proc: proc }
    return c
}

func (c *Connection)String() string {
    t := "Normal"
    if c.w == nil {
	t = "CertCheck"
    }
    return t + " for " + c.domain
}

type ConnectionProc func(net.Conn, chan bool, *Connection) (error, bool)

func (c *Connection)ReqWriteProxy(conn net.Conn) {
    c.r.WriteProxy(conn)
}

func (c *Connection)Hijack() net.Conn {
    h, _ := c.w.(http.Hijacker)
    conn, _, _ := h.Hijack()
    return conn
}

func (c *Connection)Domain() string {
    return c.domain
}

func (c *Connection)GetOutProxy() *outproxy.OutProxy {
    return c.outproxy
}

func (c *Connection)SetOutProxy(o *outproxy.OutProxy) {
    c.outproxy = o
}
