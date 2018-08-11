// go-multiproxier/upstream
//
// MIT License Copyright(c) 2018 Hiroshi Shimamoto
// vim:set sw=4 sts=4:
//

package upstream

import (
    "crypto/tls"
    "errors"
    "io"
    "io/ioutil"
    "log"
    "net"
    "net/http"
    "os"
    "strings"
    "time"

    "github.com/hshimamoto/go-multiproxier/cluster"
    "github.com/hshimamoto/go-multiproxier/connection"
    "github.com/hshimamoto/go-multiproxier/outproxy"
    "github.com/hshimamoto/go-multiproxier/webhost"
)

type Upstream struct {
    Listen string
    MiddleAddr string
    Clusters [](*cluster.Cluster)
    TempClusters [](*cluster.Cluster)
    DefaultCluster *cluster.Cluster
    DirectHosts [](*webhost.WebHost)
    BlockHosts [](*webhost.BlockHost)
    //
    CertCheckInterval time.Duration
}

func certcheckThisConn(conn net.Conn, done chan bool, c *connection.Connection) (error, bool) {
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

func tryThisConn(conn net.Conn, done chan bool, c *connection.Connection) (error, bool) {
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

func (up *Upstream)checkBlock(host string) bool {
    for _, d := range(up.BlockHosts) {
	if d.Match(host) {
	    d.Blocked++
	    return true
	}
    }
    return false
}

func (up *Upstream)checkDirect(host string) bool {
    for _, d := range(up.DirectHosts) {
	if d.Match(host) {
	    return true
	}
    }
    return false
}

func (up *Upstream)lookupCluster(host string) *cluster.Cluster {
    for _, cluster := range(up.Clusters) {
	if cluster.Host.Match(host) {
	    return cluster
	}
    }
    for _, cluster := range(up.TempClusters) {
	if cluster.Host.Match(host) {
	    cluster.Expire = time.Now().Add(time.Hour)
	    return cluster
	}
    }
    if len(up.TempClusters) > 100 {
	return up.DefaultCluster
    }
    // create temporary
    tcl := cluster.New()
    up.DefaultCluster.Lock()
    for e := up.DefaultCluster.OutProxies.Front(); e != nil; e = e.Next() {
	outproxy := e.Value.(*outproxy.OutProxy)
	tcl.OutProxies.PushBack(outproxy)
    }
    up.DefaultCluster.Unlock()
    tcl.Host = *webhost.NewWebHost(host)
    tcl.CertHost = "Temporary for " + host
    tcl.Expire = time.Now().Add(time.Hour)
    up.TempClusters = append(up.TempClusters, tcl)
    return tcl
}

func (up *Upstream)handleConnect(w http.ResponseWriter,r *http.Request) {
    port := r.URL.Port()
    host := r.URL.Hostname()
    if up.checkBlock(host) {
	log.Println("block " + host)
	w.WriteHeader(http.StatusForbidden)
	return
    }
    if port != "443" || up.checkDirect(host) {
	log.Println("direct connection")
	rconn, err := net.DialTimeout("tcp", up.MiddleAddr, 10 * time.Second)
	if err != nil {
	    log.Println("net.Dial:", err)
	    return
	}
	defer rconn.Close()

	// start hijacking
	h, _ := w.(http.Hijacker)
	lconn, _, _ := h.Hijack()
	defer lconn.Close()

	r.WriteProxy(rconn)

	connection.Transfer(lconn, rconn)

	return
    }
    // cluster
    cluster := up.lookupCluster(host)
    log.Println("cluster:", cluster)

    c := connection.New(host, r, w, tryThisConn)
    err := cluster.HandleConnection(up.MiddleAddr, c)
    if err != nil {
	// TODO: do something?
	w.WriteHeader(http.StatusForbidden)
	return
    }
    // temporary cluster
}

func (up *Upstream)handleHTTP(w http.ResponseWriter, r *http.Request) {
    conn, err := net.Dial("tcp", up.MiddleAddr) // Dial to upstream
    if err != nil {
	log.Println("net.Dial:", err)
	w.WriteHeader(http.StatusInternalServerError)
	return
    }
    defer conn.Close() // don't forget close

    if r.Header.Get("Proxy-Connection") == "Keep-Alive" {
	// close if Proxy-Connection exists
	r.Header.Set("Proxy-Connection", "close")
    }
    // always close
    r.Header.Set("Connection", "close")

    r.WriteProxy(conn)
    h, _ := w.(http.Hijacker)
    lconn, _, _ := h.Hijack()
    defer lconn.Close()

    io.Copy(lconn, conn)
}

func (up *Upstream)Handler(w http.ResponseWriter, r *http.Request) {
    log.Println(r.Method, r.URL)

    if r.Method == http.MethodConnect {
	up.handleConnect(w, r)
    } else {
	if r.URL.Host == "" {
	    up.handleAPI(w, r)
	} else {
	    up.handleHTTP(w, r)
	}
    }
}

func (up *Upstream)CertCheckCluster(domain string, cluster *cluster.Cluster) {
    // do background
    go func() {
	log.Println("Start CertCheck " + domain + " cluster:", cluster)

	c := connection.New(domain, nil, nil, certcheckThisConn)
	err := cluster.HandleConnection(up.MiddleAddr, c)
	if err != nil {
	    cluster.CertOK = nil
	    log.Println("Fail CertCheck " + domain + " cluster:", cluster)
	    return
	}
	t := time.Now()
	cluster.CertOK = &t
	log.Println("Done CertCheck " + domain + " cluster:", cluster)
    }()
}

func (up *Upstream)DoCertCheck() {
    for _, cluster := range(up.Clusters) {
	go up.CertCheckCluster(cluster.CertHost, cluster)
	time.Sleep(time.Second)
    }
}

func (up *Upstream)CertChecker() {
    for {
	go up.DoCertCheck()
	time.Sleep(up.CertCheckInterval)
    }
}

func (up *Upstream)HouseKeeper() {
    for {
	// TODO: NEED lock for temp cluster
	plen := len(up.TempClusters)
	tcls := [](*cluster.Cluster){}
	for _, c := range(up.TempClusters) {
	    if c.Expire.After(time.Now()) {
		tcls = append(tcls, c)
	    }
	}
	up.TempClusters = tcls
	if plen != len(tcls) {
	    log.Printf("HouseKeeper: reduce temp clusters %d to %d\n", plen, len(tcls))
	}
	time.Sleep(10 * time.Minute)
    }
}

func (up *Upstream)Serve() {
    go up.CertChecker()
    go up.HouseKeeper()
    http.ListenAndServe(up.Listen, http.HandlerFunc(up.Handler))
}

func NewUpstream(path string) (*Upstream, error) {
    up := &Upstream{}
    up.DirectHosts = [](*webhost.WebHost){}
    up.BlockHosts = [](*webhost.BlockHost){}
    up.Clusters = [](*cluster.Cluster){}
    up.TempClusters = [](*cluster.Cluster){}

    f, err := os.Open(path)
    if err != nil {
	return nil, err
    }
    defer f.Close()

    config, err := ioutil.ReadAll(f)
    if err != nil {
	return nil, err
    }

    lines := strings.Split(string(config), "\n")
    key := ""
    proxies := [](*outproxy.OutProxy){}
    wilds := [](*cluster.Cluster){}
    nowilds := [](*cluster.Cluster){}
    now := time.Now()
    for _, line := range(lines) {
	if line == "" || line[0] == '#' {
	    continue
	}
	if line[0] == '[' {
	    key = line
	    continue
	}
	switch key {
	case "[server]":
	    up.Listen = line
	case "[upstream]":
	    proxies = append(proxies, &outproxy.OutProxy { Addr: line, Bad: now, Timeout: 5 * time.Second, NumRunning: 0 })
	case "[proxy]":
	    up.MiddleAddr = line
	case "[direct]":
	    up.DirectHosts = append(up.DirectHosts, webhost.NewWebHost(line))
	case "[cluster]":
	    cluster := cluster.New()
	    l := strings.Split(line, "=")
	    cluster.CertHost = l[0]
	    cluster.Host = *webhost.NewWebHost(l[1])
	    if cluster.Host.Wild {
		wilds = append(wilds, cluster)
	    } else {
		nowilds = append(nowilds, cluster)
	    }
	case "[block]":
	    up.BlockHosts = append(up.BlockHosts, webhost.NewBlockHost(line))
	}
    }
    up.Clusters = append(nowilds, wilds...)
    for _, cluster := range(up.Clusters) {
	for _, proxy := range(proxies) {
	    cluster.OutProxies.PushBack(proxy)
	}
	cluster.CertOK = nil
	log.Println("cluster:", cluster)
    }
    up.DefaultCluster = cluster.New()
    up.DefaultCluster.CertHost = "DEFAULT"
    for _, proxy := range(proxies) {
	up.DefaultCluster.OutProxies.PushBack(proxy)
    }
    log.Println("default cluster:", up.DefaultCluster)
    // fast certcheck
    up.CertCheckInterval = 10 * time.Minute

    return up, nil
}
