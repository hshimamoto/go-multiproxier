// go-multiproxier / upstream.go
//
// MIT License Copyright(c) 2018 Hiroshi Shimamoto
// vim:set sw=4 sts=4:
//

package main

import (
    "container/list"
    "fmt"
    "io"
    "io/ioutil"
    "log"
    "net/http"
    "net"
    "os"
    "strings"
    "sync"
    "time"

    "github.com/hshimamoto/go-multiproxier/connection"
    "github.com/hshimamoto/go-multiproxier/webhost"
)

type Upstream struct {
    Listen string
    MiddleAddr string
    Clusters [](*Cluster)
    TempClusters [](*Cluster)
    DefaultCluster *Cluster
    DirectHosts [](*webhost.WebHost)
    BlockHosts [](*webhost.BlockHost)
    //
    CertCheckInterval time.Duration
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

func (up *Upstream)lookupCluster(host string) *Cluster {
    for _, cluster := range(up.Clusters) {
	if cluster.Host.Match(host) {
	    return cluster
	}
    }
    for _, cluster := range(up.TempClusters) {
	if cluster.Host.Match(host) {
	    cluster.expire = time.Now().Add(time.Hour)
	    return cluster
	}
    }
    if len(up.TempClusters) > 100 {
	return up.DefaultCluster
    }
    // create temporary
    tcl := &Cluster{}
    tcl.OutProxies = list.New()
    up.DefaultCluster.m.Lock()
    for e := up.DefaultCluster.OutProxies.Front(); e != nil; e = e.Next() {
	outproxy := e.Value.(*OutProxy)
	tcl.OutProxies.PushBack(outproxy)
    }
    up.DefaultCluster.m.Unlock()
    tcl.Host = *webhost.NewWebHost(host)
    tcl.CertHost = "Temporary for " + host
    tcl.expire = time.Now().Add(time.Hour)
    tcl.m = new(sync.Mutex)
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

    c := &Connection{ domain: host, r: r, w: w, proc: tryThisConn }
    err := cluster.handleConnection(up.MiddleAddr, c)
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
    dc.m.Lock()
    for e := dc.OutProxies.Front(); e != nil; e = e.Next() {
	outproxy := e.Value.(*OutProxy)
	out += outproxy.Line()
    }
    dc.m.Unlock()
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
	outproxy := e.Value.(*OutProxy)
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
    cluster := func() *Cluster {
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
	cluster.m.Lock()
	e := cluster.OutProxies.Front()
	cluster.OutProxies.MoveToBack(e)
	outproxy := e.Value.(*OutProxy)
	cluster.m.Unlock()
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
    cluster := func() *Cluster {
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
	cluster.m.Lock()
	e := cluster.OutProxies.Front()
	cluster.OutProxies.MoveToBack(e)
	outproxy := e.Value.(*OutProxy)
	cluster.m.Unlock()
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
    up.DefaultCluster.m.Lock()
    outproxy := func() *OutProxy {
	for e := up.DefaultCluster.OutProxies.Front(); e != nil; e = e.Next() {
	    o := e.Value.(*OutProxy)
	    if o.Addr == name {
		return o
	    }
	}
	return nil
    }()
    up.DefaultCluster.m.Unlock()
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

func (up *Upstream)CertCheckCluster(domain string, cluster *Cluster) {
    // do background
    go func() {
	log.Println("Start CertCheck " + domain + " cluster:", cluster)

	c := &Connection{ domain: domain, proc: certcheckThisConn }
	err := cluster.handleConnection(up.MiddleAddr, c)
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
	tcls := [](*Cluster){}
	for _, c := range(up.TempClusters) {
	    if c.expire.After(time.Now()) {
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
    up.Clusters = [](*Cluster){}
    up.TempClusters = [](*Cluster){}

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
    proxies := [](*OutProxy){}
    wilds := [](*Cluster){}
    nowilds := [](*Cluster){}
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
	    proxies = append(proxies, &OutProxy { Addr: line, Bad: now, Timeout: 5 * time.Second, NumRunning: 0 })
	case "[proxy]":
	    up.MiddleAddr = line
	case "[direct]":
	    up.DirectHosts = append(up.DirectHosts, webhost.NewWebHost(line))
	case "[cluster]":
	    cluster := &Cluster{}
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
	cluster.OutProxies = list.New()
	for _, proxy := range(proxies) {
	    cluster.OutProxies.PushBack(proxy)
	}
	cluster.m = new(sync.Mutex)
	cluster.CertOK = nil
	log.Println("cluster:", cluster)
    }
    up.DefaultCluster = &Cluster{}
    up.DefaultCluster.CertHost = "DEFAULT"
    up.DefaultCluster.OutProxies = list.New()
    for _, proxy := range(proxies) {
	up.DefaultCluster.OutProxies.PushBack(proxy)
    }
    up.DefaultCluster.m = new(sync.Mutex)
    log.Println("default cluster:", up.DefaultCluster)
    // fast certcheck
    up.CertCheckInterval = 10 * time.Minute

    return up, nil
}
