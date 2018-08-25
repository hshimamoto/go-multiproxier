// go-multiproxier/conn
//
// MIT License Copyright(c) 2018 Hiroshi Shimamoto
// vim:set sw=4 sts=4:
//

package connection

import (
    "crypto/tls"
    "fmt"
    "io"
    "net"
    "net/http"
    "strings"
    "time"

    "github.com/hshimamoto/go-multiproxier/log"
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

func (c *Connection)CheckGoogle(conn net.Conn, client *tls.Conn, done chan bool) (error, bool) {
    outer := c.GetOutProxy()

    getreq := "GET /search?source=hp&q=proxy HTTP/1.1\r\n"
    getreq += "Host: www.google.com\r\n"
    getreq += "User-Agent: Mozilla/5.0 Gecko/20100101 Firefox/61.0\r\n"
    getreq += "Accept: */*\r\n"
    getreq += "\r\n"
    client.Write([]byte(getreq))

    buf := make([]byte, 4096)
    client.SetReadDeadline(time.Now().Add(outer.Timeout))
    n, err := client.Read(buf)
    if n > 0 {
	resp := string(buf[:n])
	if strings.Index(resp, `https://www.google.com/sorry/index?continue`) > 0 {
	    return fmt.Errorf("Google detect"), false
	}
    } else {
	if err != nil {
	    return fmt.Errorf("waiting GET / response %v", err), false
	}
	return fmt.Errorf("remote TLS connection closed"), false
    }

    // send done in background
    go func() {
	defer conn.Close()
	log.Println("done certcheck for " + c.Domain() + " ok")
	done <- true
    }()

    return nil, false
}

func (c *Connection)CertCheck(conn net.Conn, done chan bool) (error, bool) {
    outer := c.GetOutProxy()
    msg := "CONNECT " + c.Domain() + ":443 HTTP/1.0\r\n\r\n"
    conn.Write([]byte(msg))
    buf, err := outer.CheckConnect(conn, "certcheckThisConn")
    if err != nil {
	return err, true
    }
    err = CheckConnectOK(string(buf))
    if err != nil {
	return fmt.Errorf("Server returns error: %v", err), true
    }

    log.Println("start certcheck communication for " + c.Domain() + " with " + outer.Addr)

    client := tls.Client(conn, &tls.Config{ ServerName: c.Domain() })
    defer client.Close()

    err = client.Handshake()
    if err != nil {
	return err, false // no penalty
    }
    log.Println("cert for " + c.Domain() + " good")

    if c.Domain() == "www.google.com" {
	return c.CheckGoogle(conn, client, done)
    }

    getreq := "GET / HTTP/1.1\r\n"
    getreq += "Host: " + c.Domain() + "\r\n"
    getreq += "User-Agent: curl/7.58.0\r\n"
    getreq += "Accept: */*\r\n"
    getreq += "\r\n"
    client.Write([]byte(getreq))

    buf = make([]byte, 4096)
    client.SetReadDeadline(time.Now().Add(outer.Timeout))
    n, err := client.Read(buf)
    if n > 0 {
	resp := string(buf[:n])
	if strings.Index(resp, `<title>Attention Required! | Cloudflare</title>`) > 0 {
	    return fmt.Errorf("Cloudflare detect"), false
	}
    } else {
	if err != nil {
	    return fmt.Errorf("waiting GET / response %v", err), false
	}
	return fmt.Errorf("remote TLS connection closed"), false
    }

    // send done in background
    go func() {
	defer conn.Close()
	log.Println("done certcheck for " + c.Domain() + " ok")
	done <- true
    }()

    return nil, false
}

func (c *Connection)Run(conn net.Conn, done chan bool) (error, bool) {
    outer := c.GetOutProxy()
    // send original CONNECT
    c.ReqWriteProxy(conn)
    buf, err := outer.CheckConnect(conn, "tryThisConn")
    if err != nil {
	return err, true
    }
    err = CheckConnectOK(string(buf))
    if err != nil {
	return fmt.Errorf("Server returns error: %v", err), false
    }

    log.Println("start communication for " + c.Domain() + " with " + outer.Addr)

    go func() {
	defer conn.Close()
	// start hijacking
	lconn := c.Hijack()
	defer lconn.Close()

	lconn.Write(buf)

	Transfer(lconn, conn)

	log.Println("done communication for " + c.Domain())

	done <- true
    }()

    return nil, false
}
