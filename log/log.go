// go-multiproxier/log
//
// MIT License Copyright(c) 2018 Hiroshi Shimamoto
// vim:set sw=4 sts=4:
//

package log

import (
    "io"
    "log"
    "os"
)

var logger *log.Logger = log.New(os.Stderr, "", log.LstdFlags)

func Fatal(v ...interface{}) {
    logger.Fatal(v...)
}

func Println(v ...interface{}) {
    logger.Println(v...)
}

func Printf(fmt string, v ...interface{}) {
    logger.Printf(fmt, v...)
}

func Init(w io.Writer) {
    logger = log.New(w, "", log.LstdFlags)
}
