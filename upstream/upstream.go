// go-multiproxier/upstream
//
// MIT License Copyright(c) 2018 Hiroshi Shimamoto
// vim:set sw=4 sts=4:
//

package upstream

import (
    "crypto/tls"
    "errors"
    "fmt"
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
	rconn, err := net.Dial("tcp", up.MiddleAddr)
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

func (up *Upstream)dumpOutProxies(w http.ResponseWriter, r *http.Request) {
    // ignore request
    dc := up.DefaultCluster
    out := ""
    dc.Lock()
    for e := dc.OutProxies.Front(); e != nil; e = e.Next() {
	outproxy := e.Value.(*outproxy.OutProxy)
	out += outproxy.Line()
    }
    dc.Unlock()
    w.Write([]byte(out))
}

func (up *Upstream)dumpBlockHosts(w http.ResponseWriter, r *http.Request) {
    // ignore request
    out := ""
    for _, h := range(up.BlockHosts) {
	out += fmt.Sprintf("%s %d\n", h.String(), h.Blocked)
    }
    w.Write([]byte(out))
}

func (up *Upstream)dumpClusters(w http.ResponseWriter, r *http.Request) {
    // ignore request
    for _, c := range(up.Clusters) {
	out := makeClusterBlob(c)
	w.Write([]byte(out))
    }
}

func (up *Upstream)dumpConfig(w http.ResponseWriter, r *http.Request) {
    // ignore request
    config := "# generated in program"
    config += "[server]\n"
    config += up.Listen + "\n"
    config += "[upstream]\n"
    proxies := up.DefaultCluster.OutProxies
    for e := proxies.Front(); e != nil; e = e.Next() {
	outproxy := e.Value.(*outproxy.OutProxy)
	config += outproxy.Addr + "\n"
    }
    config += "[proxy]\n"
    config += up.MiddleAddr + "\n"
    config += "[direct]\n"
    for _, h := range(up.DirectHosts) {
	config += h.String() + "\n"
    }
    config += "[cluster]\n"
    for _, c := range(up.Clusters) {
	config += c.CertHost + "=" + c.Host.String() + "\n"
    }
    config += "[block]\n"
    for _, h := range(up.BlockHosts) {
	config += h.String() + "\n"
    }
    w.Write([]byte(config))
}

func (up *Upstream)apiCluster(api []string, w http.ResponseWriter, r *http.Request) {
    if len(api) < 2 {
	return
    }
    cname := api[0]
    cmd := api[1]
    // lookup cluster
    cluster := func() *cluster.Cluster {
	for _, c := range(up.Clusters) {
	    if cname == c.CertHost {
		return c
	    }
	}
	return nil
    }()
    if cluster == nil {
	return
    }
    switch cmd {
    case "bad":
	cluster.Lock()
	e := cluster.OutProxies.Front()
	cluster.OutProxies.MoveToBack(e)
	outproxy := e.Value.(*outproxy.OutProxy)
	cluster.Unlock()
	w.Write([]byte("bad outproxy " + outproxy.Addr + "\n"))
    }
}

func (up *Upstream)apiBlock(api []string, w http.ResponseWriter, r *http.Request) {
    if len(api) < 1 {
	return
    }
    name := api[0]
    if name == "list" {
	for _, h := range(up.BlockHosts) {
	    w.Write([]byte(h.String() + "\n"))
	}
	return
    }
    on := "on"
    if len(api) >= 2 {
	if api[1] == "off" {
	    on = "off"
	}
    }
    // TODO
    w.Write([]byte("block " + name + " " + on + "\n"))
}

func (up *Upstream)apiTemp(api []string, w http.ResponseWriter, r *http.Request) {
    if len(api) < 1 {
	return
    }
    cname := api[0]
    if cname == "list" {
	for _, c := range(up.TempClusters) {
	    out := makeClusterBlob(c)
	    w.Write([]byte(out))
	}
	return
    }
    if len(api) < 2 {
	return
    }
    cmd := api[1]
    // lookup cluster
    cluster := func() *cluster.Cluster {
	for _, c := range(up.Clusters) {
	    if cname == c.CertHost {
		return c
	    }
	}
	return nil
    }()
    if cluster == nil {
	return
    }
    switch cmd {
    case "bad":
	cluster.Lock()
	e := cluster.OutProxies.Front()
	cluster.OutProxies.MoveToBack(e)
	outproxy := e.Value.(*outproxy.OutProxy)
	cluster.Unlock()
	w.Write([]byte("bad outproxy " + outproxy.Addr + "\n"))
    }
}

func (up *Upstream)apiOutProxy(api []string, w http.ResponseWriter, r *http.Request) {
    if len(api) < 2 {
	return
    }
    name := api[0]
    cmd := api[1]
    // lookup outproxy
    up.DefaultCluster.Lock()
    outproxy := func() *outproxy.OutProxy {
	for e := up.DefaultCluster.OutProxies.Front(); e != nil; e = e.Next() {
	    o := e.Value.(*outproxy.OutProxy)
	    if o.Addr == name {
		return o
	    }
	}
	return nil
    }()
    up.DefaultCluster.Unlock()
    if outproxy == nil {
	return
    }
    switch cmd {
    case "bad":
	outproxy.Bad = time.Now().Add(10 * time.Minute)
	w.Write([]byte("bad outproxy " + outproxy.Addr + "\n"))
    case "good":
	outproxy.Bad = time.Now()
	w.Write([]byte("good outproxy " + outproxy.Addr + "\n"))
    }
}

func (up *Upstream)handleAPI(w http.ResponseWriter, r *http.Request) {
    log.Println(r.URL.Query())
    dirs := strings.Split(r.URL.Path, "/")[1:] // remove first /
    log.Println(dirs)
    switch dirs[0] {
    case "config": up.dumpConfig(w, r)
    case "clusters": up.dumpClusters(w, r)
    case "outproxies": up.dumpOutProxies(w, r)
    case "blockhosts": up.dumpBlockHosts(w, r)
    case "certcheck":
	if len(dirs) > 1 {
	    switch dirs[1] {
	    case "issue":
		go up.DoCertCheck()
		w.Write([]byte("Issue certcheck\n"))
	    case "fast":
		up.CertCheckInterval = 10 * time.Minute
		w.Write([]byte("Set certcheck fast\n"))
	    case "slow":
		up.CertCheckInterval = time.Hour
		w.Write([]byte("Set certcheck slow\n"))
	    }
	} else {
	    go up.DoCertCheck()
	    w.Write([]byte("Issue certcheck\n"))
	}
    case "cluster": up.apiCluster(dirs[1:], w, r)
    case "block": up.apiBlock(dirs[1:], w, r)
    case "temp": up.apiTemp(dirs[1:], w, r)
    case "outproxy": up.apiOutProxy(dirs[1:], w, r)
    }
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
