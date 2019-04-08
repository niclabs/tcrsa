package main

import (
	"flag"
	"fmt"
)

var k uint64
var l uint64
var s int
var m string

func init() {
	flag.Uint64Var(&k, "k", 3, "Threshold size")
	flag.Uint64Var(&l, "l", 5, "Number of shares")
	flag.IntVar(&s, "s", 1024, "key size")
	flag.StringVar(&m, "m", "hello world", "message")
}

func main() {
	flag.Parse()

	keyShares, err := GenerateKeys(s, k, l, nil)
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}


}