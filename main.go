// go-multiproxier
//
// MIT License Copyright(c) 2018 Hiroshi Shimamoto
// vim:set sw=4 sts=4:
//
// ./go-multiproxier <config file>
//

package main

import (
    "crypto/tls"
    "errors"
    "log"
    "net"
    "net/http"
    "os"
    "runtime"
    "strings"
    "time"

    "github.com/hshimamoto/go-multiproxier/connection"
)

var timeout time.Duration = 10 * time.Second

func checkConnectOK(resp string) error {
    lines := strings.Split(resp, "\r\n")
    codes := strings.Split(lines[0], " ")
    if codes[1] != "200" {
	return errors.New(lines[0])
    }
    return nil
}

func openProxy(proxy, outproxy string) (*net.TCPConn, error, bool) {
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
	return nil, errors.New("READ NG"), true
    }
    err = checkConnectOK(string(buf[:n]))
    if err != nil {
	conn.Close()
	return nil, errors.New("CONNECT NG " + err.Error()), true
    }
    return conn.(*net.TCPConn), nil, false
}

type Connection struct {
    domain string
    r *http.Request
    w http.ResponseWriter
    proc ConnectionProc
    outproxy *OutProxy
}

func (c *Connection)String() string {
    t := "Normal"
    if c.w == nil {
	t = "CertCheck"
    }
    return t + " for " + c.domain
}

type ConnectionProc func(*net.TCPConn, chan bool, *Connection) (error, bool)

func certcheckThisConn(conn *net.TCPConn, done chan bool, c *Connection) (error, bool) {
    outproxy := c.outproxy
    msg := "CONNECT " + c.domain + ":443 HTTP/1.0\r\n\r\n"
    conn.Write([]byte(msg))
    buf, err := outproxy.checkConnect(conn, "certcheckThisConn")
    if err != nil {
	return err, true
    }
    err = checkConnectOK(string(buf))
    if err != nil {
	return errors.New("Server returns error:" + err.Error()), true
    }

    log.Println("start certcheck communication for " + c.domain + " with " + c.outproxy.Addr)

    client := tls.Client(conn, &tls.Config{ ServerName: c.domain })
    defer client.Close()

    err = client.Handshake()
    if err != nil {
	return err, false // no penalty
    }
    log.Println("cert for " + c.domain + " good")

    getreq := "GET / HTTP/1.1\r\n"
    getreq += "Host: " + c.domain + "\r\n"
    getreq += "User-Agent: curl/7.58.0\r\n"
    getreq += "Accept: */*\r\n"
    getreq += "\r\n"
    client.Write([]byte(getreq))

    buf = make([]byte, 4096)
    client.SetReadDeadline(time.Now().Add(outproxy.Timeout))
    n, err := client.Read(buf)
    if n > 0 {
	resp := string(buf[:n])
	if strings.Index(resp, `<title>Attention Required! | Cloudflare</title>`) > 0 {
	    return errors.New("Cloudflare detect"), false
	}
	if strings.Index(resp, `<script src="https://www.google.com/recaptcha/api.js" async defer></script>`) > 0 {
	    return errors.New("Google detect"), false
	}
    } else {
	if err != nil {
	    return errors.New("waiting GET / response " + err.Error()), false
	}
	return errors.New("remote TLS connection closed"), false
    }

    // send done in background
    go func() {
	defer conn.Close()
	log.Println("done certcheck for " + c.domain + " ok")
	done <- true
    }()

    return nil, false
}

func tryThisConn(conn *net.TCPConn, done chan bool, c *Connection) (error, bool) {
    outproxy := c.outproxy
    // send original CONNECT
    c.r.WriteProxy(conn)
    buf, err := outproxy.checkConnect(conn, "tryThisConn")
    if err != nil {
	return err, true
    }
    err = checkConnectOK(string(buf))
    if err != nil {
	return errors.New("Server returns error:" + err.Error()), false
    }

    log.Println("start communication for " + c.domain + " with " + c.outproxy.Addr)

    go func() {
	defer conn.Close()
	// start hijacking
	h, _ := c.w.(http.Hijacker)
	lconn, _, _ := h.Hijack()
	defer lconn.Close()

	lconn.Write(buf)

	connection.Transfer(lconn, conn)

	log.Println("done communication for " + c.domain)

	done <- true
    }()

    return nil, false
}

func makeClusterBlob(c *Cluster) string {
    out := c.CertHost + "=" + c.Host.String() + "\n"
    if c.CertOK != nil {
	out += "check time:" + c.CertOK.Format(time.ANSIC) + "\n"
    } else {
	out += "bad cluster\n"
    }
    c.m.Lock()
    for e := c.OutProxies.Front(); e != nil; e = e.Next() {
	outproxy := e.Value.(*OutProxy)
	out += " " + outproxy.Line()
    }
    c.m.Unlock()
    return out
}

func main() {
    if len(os.Args) < 2 {
	log.Fatal("Need config")
    }
    up, err := NewUpstream(os.Args[1])
    if err != nil {
	log.Fatal("NewUpstream:", err)
    }
    // going to multithread
    cpus := runtime.NumCPU()
    if cpus > 4 {
	cpus = 4
    }
    log.Println("set GOMAXPROCS:", cpus)
    runtime.GOMAXPROCS(cpus)
    up.Serve()
}
