// go-multiproxier/upstream / api.go
//
// MIT License Copyright(c) 2018 Hiroshi Shimamoto
// vim:set sw=4 sts=4:
//

package upstream

import (
    "fmt"
    "net/http"
    "strings"
    "time"

    "github.com/hshimamoto/go-multiproxier/cluster"
    "github.com/hshimamoto/go-multiproxier/log"
    "github.com/hshimamoto/go-multiproxier/outproxy"
)

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
    case "show":
	w.Write([]byte(makeClusterBlob(cluster)))
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
	for _, c := range(up.TempClusters) {
	    if "Temporary for " + cname == c.CertHost {
		return c
	    }
	}
	return nil
    }()
    if cluster == nil {
	return
    }
    switch cmd {
    case "show":
	w.Write([]byte(makeClusterBlob(cluster)))
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
