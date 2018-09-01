// go-multiproxier/cluster
//
// MIT License Copyright(c) 2018 Hiroshi Shimamoto
// vim:set sw=4 sts=4:
//

package cluster

import (
    "container/list"
    "errors"
    "net"
    "net/http"
    "sync"
    "time"

    "github.com/hshimamoto/go-multiproxier/connection"
    "github.com/hshimamoto/go-multiproxier/log"
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
    sentinel := 0

    for e != nil {
	sentinel++
	if sentinel > 128 {
	    log.Printf("something wrong for %s\n", c.Domain())
	    return errors.New("bad in handleConnection")
	}
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
	    cl.m.Lock()
	    e = e.Next()
	    cl.m.Unlock()
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

func (cl *Cluster)Lock() {
    cl.m.Lock()
}

func (cl *Cluster)Unlock() {
    cl.m.Unlock()
}

func certcheckThisConn(conn net.Conn, done chan bool, c *connection.Connection) (error, bool) {
    return c.CertCheck(conn, done)
}

func tryThisConn(conn net.Conn, done chan bool, c *connection.Connection) (error, bool) {
    return c.Run(conn, done)
}

func (cl *Cluster)CertCheck(proxy string) {
    log.Printf("Start CertCheck %s cluster: %v\n", cl.CertHost, cl)
    conn := connection.New(cl.CertHost, nil, nil, certcheckThisConn)
    err := cl.handleConnection(proxy, conn)
    if err != nil {
	cl.CertOK = nil
	log.Printf("Fail CertCheck %s cluster: %v\n", cl.CertHost, cl)
	return
    }
    t := time.Now()
    cl.CertOK = &t
    log.Printf("Done CertCheck %s cluster: %v\n", cl.CertHost, cl)
}

func (cl *Cluster)Run(proxy, host string, w http.ResponseWriter,r *http.Request) {
    conn := connection.New(host, r, w, tryThisConn)
    err := cl.handleConnection(proxy, conn)
    if err != nil {
	// TODO: do something?
	w.WriteHeader(http.StatusForbidden)
    }
}
