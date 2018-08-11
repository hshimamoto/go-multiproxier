// go-multiproxier/cluster
//
// MIT License Copyright(c) 2018 Hiroshi Shimamoto
// vim:set sw=4 sts=4:
//

package cluster

import (
    "container/list"
    "crypto/tls"
    "errors"
    "fmt"
    "log"
    "net"
    "net/http"
    "strings"
    "sync"
    "time"

    "github.com/hshimamoto/go-multiproxier/connection"
    "github.com/hshimamoto/go-multiproxier/outproxy"
    "github.com/hshimamoto/go-multiproxier/webhost"
)

type Cluster struct {
    Host webhost.WebHost
    CertHost string
    OutProxies *list.List
    CertOK *time.Time
    m *sync.Mutex
    Expire time.Time
}

func New() *Cluster {
    c := &Cluster{}
    c.OutProxies = list.New()
    c.m = new(sync.Mutex)
    return c
}

func (cl *Cluster)String() string {
    return cl.CertHost
}

func (cl *Cluster)handleConnectionTry(proxy string, c *connection.Connection, done chan bool) (error, bool) {
    outer := c.GetOutProxy()
    p := outer.Addr
    log.Println("try " + p + " for " + c.Domain())

    var conn net.Conn = nil
    var err error
    var penalty bool
    if proxy != "" {
	conn, err, penalty = connection.OpenProxy(proxy, p) // open the 1st proxy
	if err != nil {
	    if penalty {
		// 10min.
		outer.Bad = time.Now().Add(10 * time.Minute)
	    }
	    return err, !penalty // 1st proxy error is critical
	}
    } else {
	// no 1st proxy, just Dial to outproxy
	pconn, err := net.DialTimeout("tcp", p, outer.Timeout)
	if err != nil {
	    // 10min.
	    outer.Bad = time.Now().Add(10 * time.Minute)
	    return err, false
	}
	conn = pconn.(*net.TCPConn)
    }
    err, penalty = c.Proc(conn, done, c)
    if err != nil {
	log.Println("Connection:", c, err)
	conn.Close()
	if penalty {
	    outer.Bad = time.Now().Add(10 * time.Minute)
	}
	return err, false
    }
    // everything fine
    outer.Bad = time.Now()
    outer.NumRunning++
    log.Println(p, outer.NumRunning, "running")
    return nil, false
}

func (cl *Cluster)handleConnection(proxy string, c *connection.Connection) error {
    cl.m.Lock()
    e := cl.OutProxies.Front()
    cl.m.Unlock()

    used := [](*outproxy.OutProxy){}

    for e != nil {
	outer := e.Value.(*outproxy.OutProxy)
	if outer.Bad.After(time.Now()) {
	    cl.m.Lock()
	    e = e.Next()
	    cl.m.Unlock()
	    continue
	}
	unused := func() bool {
	    for _, prev := range(used) {
		if prev == outer {
		    return false
		}
	    }
	    return true
	}()
	if !unused {
	    continue
	}
	used = append(used, outer)
	done := make(chan bool)
	c.SetOutProxy(outer)
	err, critical := cl.handleConnectionTry(proxy, c, done)
	if err != nil {
	    if critical {
		log.Println("CRITICAL ", err)
		break
	    }
	    cl.m.Lock()
	    next := e.Next()
	    cl.OutProxies.MoveToBack(e)
	    e = next
	    cl.m.Unlock()
	    outer.Fail++
	    continue
	}
	cl.m.Lock()
	cl.OutProxies.MoveToFront(e)
	cl.m.Unlock()
	// wait
	<-done
	outer.NumRunning--
	outer.Success++
	return nil
    }
    log.Println("ERR No proxy found for " + c.Domain())
    return errors.New("No good proxy")
}

func (c *Cluster)Lock() {
    c.m.Lock()
}

func (c *Cluster)Unlock() {
    c.m.Unlock()
}

func certcheckThisConn(conn net.Conn, done chan bool, c *connection.Connection) (error, bool) {
    outer := c.GetOutProxy()
    msg := "CONNECT " + c.Domain() + ":443 HTTP/1.0\r\n\r\n"
    conn.Write([]byte(msg))
    buf, err := outer.CheckConnect(conn, "certcheckThisConn")
    if err != nil {
	return err, true
    }
    err = connection.CheckConnectOK(string(buf))
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
	if strings.Index(resp, `<script src="https://www.google.com/recaptcha/api.js" async defer></script>`) > 0 {
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

func tryThisConn(conn net.Conn, done chan bool, c *connection.Connection) (error, bool) {
    outer := c.GetOutProxy()
    // send original CONNECT
    c.ReqWriteProxy(conn)
    buf, err := outer.CheckConnect(conn, "tryThisConn")
    if err != nil {
	return err, true
    }
    err = connection.CheckConnectOK(string(buf))
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

	connection.Transfer(lconn, conn)

	log.Println("done communication for " + c.Domain())

	done <- true
    }()

    return nil, false
}

func (c *Cluster)CertCheck(proxy string) {
    log.Printf("Start CertCheck %s cluster: %v\n", c.CertHost, c)
    conn := connection.New(c.CertHost, nil, nil, certcheckThisConn)
    err := c.handleConnection(proxy, conn)
    if err != nil {
	c.CertOK = nil
	log.Printf("Fail CertCheck %s cluster: %v\n", c.CertHost, c)
	return
    }
    t := time.Now()
    c.CertOK = &t
    log.Printf("Done CertCheck %s cluster: %v\n", c.CertHost, c)
}

func (c *Cluster)Run(proxy, host string, w http.ResponseWriter,r *http.Request) {
    conn := connection.New(host, r, w, tryThisConn)
    err := c.handleConnection(proxy, conn)
    if err != nil {
	// TODO: do something?
	w.WriteHeader(http.StatusForbidden)
    }
}
