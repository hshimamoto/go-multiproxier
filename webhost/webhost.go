// go-multiproxier/webhost
//
// MIT License Copyright(c) 2018 Hiroshi Shimamoto
// vim:set sw=4 sts=4:
//

package webhost

import (
    "strings"
)

type WebHost struct {
    Domain string
    Wild bool
    DomainLen int
}

func (wh *WebHost)String() string {
    out := ""
    if wh.Wild {
	out = "*."
    }
    return out + wh.Domain
}

func NewWebHost(host string) *WebHost {
    wh := &WebHost{}
    a := strings.Split(host, ".")
    if a[0] == "*" {
	wh.Wild = true
	wh.DomainLen = len(a) - 1
	wh.Domain = strings.Join(a[1:], ".")
    } else {
	wh.Wild = false
	wh.Domain = host
    }
    return wh
}

func (wh *WebHost)Match(host string) bool {
    if wh.Wild {
	a := strings.Split(host, ".")
	if len(a) < wh.DomainLen {
	    return false
	}
	l := len(a) - wh.DomainLen
	domain := strings.Join(a[l:], ".")
	return wh.Domain == domain
    }
    return wh.Domain == host
}

type BlockHost struct {
    wh *WebHost
    Blocked int
}

func (bh *BlockHost)String() string {
    return bh.wh.String()
}

func (bh *BlockHost)Match(host string) bool {
    return bh.wh.Match(host)
}

func NewBlockHost(host string) *BlockHost {
    return &BlockHost{wh: NewWebHost(host), Blocked: 0}
}
