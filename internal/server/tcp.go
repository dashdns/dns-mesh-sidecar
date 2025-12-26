package server

import (
	"net"

	"github.com/rs/zerolog/log"

	"lktr/internal/dns"
)

type TCPServer struct {
	ListenAddr string
	Handler    *dns.Handler
	Verbose    bool
}

func NewTCPServer(listenAddr string, handler *dns.Handler, verbose bool) *TCPServer {
	return &TCPServer{
		ListenAddr: listenAddr,
		Handler:    handler,
		Verbose:    verbose,
	}
}

func (s *TCPServer) Start() error {
	listener, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		log.Err(err).Msgf("failed to listen on TCP %s", s.ListenAddr)
		return err
	}
	defer listener.Close()

	log.Info().Msgf("DNS proxy listening on TCP %s\n", s.ListenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Err(err).Msg("Error accepting TCP connection:")
			continue
		}

		go s.Handler.HandleTCP(conn)
	}
}
