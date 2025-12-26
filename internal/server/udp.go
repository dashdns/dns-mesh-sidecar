package server

import (
	"net"

	"github.com/rs/zerolog/log"

	"lktr/internal/dns"
)

type UDPServer struct {
	ListenAddr string
	Handler    *dns.Handler
	Verbose    bool
}

func NewUDPServer(listenAddr string, handler *dns.Handler, verbose bool) *UDPServer {
	return &UDPServer{
		ListenAddr: listenAddr,
		Handler:    handler,
		Verbose:    verbose,
	}
}

func (s *UDPServer) Start() error {
	addr, err := net.ResolveUDPAddr("udp", s.ListenAddr)
	if err != nil {
		log.Err(err).Msg("failed to resolve UDP address:")
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Err(err).Msgf("failed to listen on UDP %s", s.ListenAddr)
		return err
	}
	defer conn.Close()

	log.Info().Msgf("DNS proxy listening on UDP %s\n", s.ListenAddr)

	buffer := make([]byte, 512)

	for {
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Err(err).Msgf("Error reading from UDP:")
			continue
		}

		if s.Verbose {
			log.Info().Msgf("Received %d bytes from %s", n, clientAddr)
		}

		queryCopy := make([]byte, n)
		copy(queryCopy, buffer[:n])

		go s.Handler.HandleUDP(conn, clientAddr, queryCopy)
	}
}
