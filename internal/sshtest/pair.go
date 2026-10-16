package sshtest

import (
	"encoding/pem"
	"net"
)

func pemEncode(typ string, b []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b})
}

// tcpPair returns two ends of a loopback TCP connection. Unlike net.Pipe,
// both ends support CloseWrite, so half-close can be tested end to end.
func tcpPair() (net.Conn, net.Conn, error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	defer ln.Close()
	a, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		return nil, nil, err
	}
	b, err := ln.Accept()
	if err != nil {
		a.Close()
		return nil, nil, err
	}
	return a, b, nil
}
