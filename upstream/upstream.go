// go-multiproxier/upstream
//
// MIT License Copyright(c) 2018 Hiroshi Shimamoto
// vim:set sw=4 sts=4:
//

package upstream

import (
    "io/ioutil"
    "os"
    "strings"
    "time"

    "github.com/hshimamoto/go-multiproxier/cluster"
    "github.com/hshimamoto/go-multiproxier/log"
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
