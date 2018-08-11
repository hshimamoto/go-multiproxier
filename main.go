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
    "os"
    "runtime"
    "strings"
    "time"

    "github.com/hshimamoto/go-multiproxier/cluster"
    "github.com/hshimamoto/go-multiproxier/connection"
    "github.com/hshimamoto/go-multiproxier/outproxy"
)

func certcheckThisConn(conn *net.TCPConn, done chan bool, c *connection.Connection) (error, bool) {
    outer := c.Outproxy
    msg := "CONNECT " + c.Domain + ":443 HTTP/1.0\r\n\r\n"
    conn.Write([]byte(msg))
    buf, err := outer.CheckConnect(conn, "certcheckThisConn")
    if err != nil {
	return err, true
    }
    err = connection.CheckConnectOK(string(buf))
    if err != nil {
	return errors.New("Server returns error:" + err.Error()), true
    }

    log.Println("start certcheck communication for " + c.Domain + " with " + outer.Addr)

    client := tls.Client(conn, &tls.Config{ ServerName: c.Domain })
    defer client.Close()

    err = client.Handshake()
    if err != nil {
	return err, false // no penalty
    }
    log.Println("cert for " + c.Domain + " good")

    getreq := "GET / HTTP/1.1\r\n"
    getreq += "Host: " + c.Domain + "\r\n"
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
	log.Println("done certcheck for " + c.Domain + " ok")
	done <- true
    }()

    return nil, false
}

func tryThisConn(conn *net.TCPConn, done chan bool, c *connection.Connection) (error, bool) {
    outer := c.Outproxy
    // send original CONNECT
    c.ReqWriteProxy(conn)
    buf, err := outer.CheckConnect(conn, "tryThisConn")
    if err != nil {
	return err, true
    }
    err = connection.CheckConnectOK(string(buf))
    if err != nil {
	return errors.New("Server returns error:" + err.Error()), false
    }

    log.Println("start communication for " + c.Domain + " with " + outer.Addr)

    go func() {
	defer conn.Close()
	// start hijacking
	lconn := c.Hijack()
	defer lconn.Close()

	lconn.Write(buf)

	connection.Transfer(lconn, conn)

	log.Println("done communication for " + c.Domain)

	done <- true
    }()

    return nil, false
}

func makeClusterBlob(c *cluster.Cluster) string {
    out := c.CertHost + "=" + c.Host.String() + "\n"
    if c.CertOK != nil {
	out += "check time:" + c.CertOK.Format(time.ANSIC) + "\n"
    } else {
	out += "bad cluster\n"
    }
    c.Lock()
    for e := c.OutProxies.Front(); e != nil; e = e.Next() {
	outer := e.Value.(*outproxy.OutProxy)
	out += " " + outer.Line()
    }
    c.Unlock()
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
