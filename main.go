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

    "github.com/mattn/go-isatty"
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
    // UI
    if isatty.IsTerminal(os.Stdin.Fd()) && isatty.IsTerminal(os.Stdout.Fd()) {
	// change logger
	f, err := os.OpenFile("stderr.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
	    log.Fatal("unable to change logger")
	}
	log.Init(f)
	// never close
	log.Println("logger change")
    }
    up.Serve()
}
