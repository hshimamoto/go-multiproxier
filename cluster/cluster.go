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
    "sync/atomic"
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
    log *log.LocalLog
}

func New() *Cluster {
    c := &Cluster{}
    c.OutProxies = list.New()
    c.m = new(sync.Mutex)
    c.log = log.NewLocalLog(100)
    return c
}

func (cl *Cluster)String() string {
    return cl.CertHost
}

func (cl *Cluster)Logs() []string {
    return cl.log.Get()
}

func (cl *Cluster)handleConnectionTry(proxy string, c *connection.Connection, done chan bool) (error, bool) {
    outer := c.GetOutProxy()
    p := outer.Addr
    cl.log.Printf("try %s for %s\n", p, c.Domain())

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
	cl.log.Printf("Connection: %v %v\n", c, err)
	conn.Close()
	if penalty {
	    outer.Bad = time.Now().Add(10 * time.Minute)
	}
	return err, false
    }
    // everything fine
    outer.Bad = time.Now()
    atomic.AddInt32(&outer.NumRunning, 1)
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
	    cl.log.Printf("something wrong for %s\n", c.Domain())
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
		cl.log.Printf("CRITICAL %v\n", err)
		break
	    }
	    cl.m.Lock()
	    next := e.Next()
	    cl.OutProxies.MoveToBack(e)
	    e = next
	    cl.m.Unlock()
	    atomic.AddUint32(&outer.Fail, 1)
	    continue
	}
	cl.m.Lock()
	cl.OutProxies.MoveToFront(e)
	cl.m.Unlock()
	// wait
	<-done
	atomic.AddInt32(&outer.NumRunning, -1)
	atomic.AddUint32(&outer.Success, 1)
	return nil
    }
    cl.log.Printf("ERR No proxy found for %s\n", c.Domain())
    return errors.New("No good proxy")
}

func (cl *Cluster)handleConnectionCert(proxy string) {
    success := [](*list.Element){}
    fail := [](*list.Element){}

    // create list
    cl.m.Lock()
    e := cl.OutProxies.Front()
    for e != nil {
	success = append(success, e)
	e = e.Next()
    }
    cl.Unlock()

    var wg sync.WaitGroup

    cl.log.Printf("check %d proxies\n", len(success))
    for idx, e := range success {
	elm := e
	outer := elm.Value.(*outproxy.OutProxy)
	cl.log.Printf("check %s <%d> for %s\n", outer.Addr, idx, cl.CertHost)
	wg.Add(1)
	go func() {
	    defer wg.Done()

	    if outer.Bad.After(time.Now()) {
		return
	    }
	    done := make(chan bool)
	    c := connection.New(cl.CertHost, nil, nil, certcheckThisConn, cl.log)
	    c.SetOutProxy(outer)
	    err, _ := cl.handleConnectionTry(proxy, c, done)
	    if err != nil {
		fail = append(fail, elm)
		atomic.AddUint32(&outer.Fail, 1)
		return
	    }
	    <-done
	    atomic.AddInt32(&outer.NumRunning, -1)
	    atomic.AddUint32(&outer.Success, 1)
	}()
    }

    wg.Wait()

    cl.m.Lock()
    for _, e := range fail {
	cl.OutProxies.MoveToBack(e)
    }
    cl.m.Unlock()
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
    cl.log.Printf("Start CertCheck %s cluster: %v\n", cl.CertHost, cl)
    cl.handleConnectionCert(proxy)
    cl.log.Printf("All proxies were checked %s cluster: %v\n", cl.CertHost, cl)
    conn := connection.New(cl.CertHost, nil, nil, certcheckThisConn, cl.log)
    err := cl.handleConnection(proxy, conn)
    if err != nil {
	cl.CertOK = nil
	cl.log.Printf("Fail CertCheck %s cluster: %v\n", cl.CertHost, cl)
	return
    }
    t := time.Now()
    cl.CertOK = &t
    cl.log.Printf("Done CertCheck %s cluster: %v\n", cl.CertHost, cl)
}

func (cl *Cluster)Run(proxy, host string, w http.ResponseWriter,r *http.Request) {
    conn := connection.New(host, r, w, tryThisConn, cl.log)
    err := cl.handleConnection(proxy, conn)
    if err != nil {
	// TODO: do something?
	w.WriteHeader(http.StatusForbidden)
    }
}
