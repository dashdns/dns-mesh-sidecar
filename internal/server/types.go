package server

import "lktr/internal/dns"

type TCPServer struct {
	ListenAddr string
	Handler    *dns.Handler
	Verbose    bool
}

type UDPServer struct {
	ListenAddr string
	Handler    *dns.Handler
	Verbose    bool
}
