# Golang Threshold Cryptography Library - RSA implementation 

[![Build Status](https://travis-ci.org/niclabs/tcrsa.svg?branch=master)](https://travis-ci.org/niclabs/tcrsa) [![GoDoc](https://godoc.org/github.com/niclabs/libtc-rsa?status.svg)](https://godoc.org/github.com/niclabs/tcrsa)

This library implements the cryptographic algorithms of Victor Shoup's paper [Practical Threshold Signatures] in the Golang programming language. 

The codebase, commments and optimizations were ported from a previous implementation in C language, called [tchsm-libtc](https://github.com/niclabs/tchsm-libtc). As the previous implementation, the objective of this library is to provide a set of primitives to work with.

### Requirements

Due to Golang extensive standard library, this implementation does not have external requirements (obviously aside of [Golang](https://golang.org), version 1.12 or above).

### Installing

```shell
go get https://github.com/niclabs/tcrsa
```

To run the tests you just need to use `go test`:

```shell
go test
```