// go-multiproxier / cluster.go
//
// MIT License Copyright(c) 2018 Hiroshi Shimamoto
// vim:set sw=4 sts=4:
//

package main

import (
    "container/list"
    "errors"
    "log"
    "net"
    "sync"
    "time"

    "github.com/hshimamoto/go-multiproxier/webhost"
)

type Cluster struct {
    Host webhost.WebHost
    CertHost string
    OutProxies *list.List
    CertOK *time.Time
    m *sync.Mutex
    expire time.Time
}

func (cl *Cluster)String() string {
    return cl.CertHost
}

func (cl *Cluster)handleConnectionTry(proxy string, c *Connection, done chan bool) (error, bool) {
    outproxy := c.outproxy
    p := outproxy.Addr
    log.Println("try " + p + " for " + c.domain)

    var conn *net.TCPConn = nil
    var err error
    var penalty bool
    if proxy != "" {
	conn, err, penalty = openProxy(proxy, p) // open the 1st proxy
	if err != nil {
	    if penalty {
		// 10min.
		outproxy.Bad = time.Now().Add(10 * time.Minute)
	    }
	    return err, !penalty // 1st proxy error is critical
	}
    } else {
	// no 1st proxy, just Dial to outproxy
	pconn, err := net.DialTimeout("tcp", p, outproxy.Timeout)
	if err != nil {
	    // 10min.
	    outproxy.Bad = time.Now().Add(10 * time.Minute)
	    return err, false
	}
	conn = pconn.(*net.TCPConn)
    }
    err, penalty = c.proc(conn, done, c)
    if err != nil {
	log.Println("Connection:", c, err)
	conn.Close()
	if penalty {
	    outproxy.Bad = time.Now().Add(10 * time.Minute)
	}
	return err, false
    }
    // everything fine
    outproxy.Bad = time.Now()
    outproxy.NumRunning++
    log.Println(p, outproxy.NumRunning, "running")
    return nil, false
}

func (cl *Cluster)handleConnection(proxy string, c *Connection) error {
    cl.m.Lock()
    e := cl.OutProxies.Front()
    cl.m.Unlock()

    used := [](*OutProxy){}

    for e != nil {
	outproxy := e.Value.(*OutProxy)
	if outproxy.Bad.After(time.Now()) {
	    cl.m.Lock()
	    e = e.Next()
	    cl.m.Unlock()
	    continue
	}
	unused := func() bool {
	    for _, prev := range(used) {
		if prev == outproxy {
		    return false
		}
	    }
	    return true
	}()
	if !unused {
	    continue
	}
	used = append(used, outproxy)
	done := make(chan bool)
	c.outproxy = outproxy
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
	    outproxy.Fail++
	    continue
	}
	cl.m.Lock()
	cl.OutProxies.MoveToFront(e)
	cl.m.Unlock()
	// wait
	<-done
	outproxy.NumRunning--
	outproxy.Success++
	return nil
    }
    log.Println("ERR No proxy found for " + c.domain)
    return errors.New("No good proxy")
}
