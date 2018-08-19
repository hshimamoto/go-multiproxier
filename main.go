// go-multiproxier
//
// MIT License Copyright(c) 2018 Hiroshi Shimamoto
// vim:set sw=4 sts=4:
//
// ./go-multiproxier <config file>
//

package main

import (
    "os"
    "runtime"

    "github.com/hshimamoto/go-multiproxier/log"
    "github.com/hshimamoto/go-multiproxier/upstream"
)

func main() {
    if len(os.Args) < 2 {
	log.Fatal("Need config")
    }
    up, err := upstream.NewUpstream(os.Args[1])
    if err != nil {
	log.Fatal("NewUpstream:", err)
    }
    // going to multithread
    cpus := runtime.NumCPU()
    if cpus > 4 {
	cpus = 4
    }
    log.Println("set GOMAXPROCS:", cpus)
    runtime.GOMAXPROCS(cpus)
    up.Serve()
}
