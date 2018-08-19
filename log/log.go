// go-multiproxier/log
//
// MIT License Copyright(c) 2018 Hiroshi Shimamoto
// vim:set sw=4 sts=4:
//

package log

import (
    "log"
)

func Fatal(v ...interface{}) {
    log.Fatal(v...)
}

func Println(v ...interface{}) {
    log.Println(v...)
}

func Printf(fmt string, v ...interface{}) {
    log.Printf(fmt, v...)
}
