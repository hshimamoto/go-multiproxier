// go-multiproxier/conn
//
// MIT License Copyright(c) 2018 Hiroshi Shimamoto
// vim:set sw=4 sts=4:
//

package connection

import (
    "io"
    "net"
    "time"
)

func Transfer(lconn, rconn net.Conn) {
    d1 := make(chan bool)
    d2 := make(chan bool)
    go func() {
	io.Copy(rconn, lconn)
	d1 <- true
    }()
    go func() {
	io.Copy(lconn, rconn)
	d2 <- true
    }()
    select {
    case <-d1: go func() { <-d2 }()
    case <-d2: go func() { <-d1 }()
    }
    time.Sleep(time.Second)
}
