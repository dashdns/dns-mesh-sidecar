package dns

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"lktr/pkg/matcher"
)

type Handler struct {
	UpstreamDNS string
	Verbose     bool
	Matcher     *matcher.Matcher
	mu          sync.RWMutex
}

func NewHandler(upstreamDNS string, verbose bool, m *matcher.Matcher) *Handler {
	return &Handler{
		UpstreamDNS: upstreamDNS,
		Verbose:     verbose,
		Matcher:     m,
	}
}

func (h *Handler) UpdateMatcher(m *matcher.Matcher) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Matcher = m
	if h.Verbose {
		log.Printf("Matcher updated successfully")
	}
}

func (h *Handler) getMatcher() *matcher.Matcher {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.Matcher
}

func (h *Handler) HandleUDP(serverConn *net.UDPConn, clientAddr *net.UDPAddr, query []byte) {
	domain, qtype := ParseQuery(query)

	if domain != "" {
		fmt.Printf("[UDP] %s -> %s (%s)\n", clientAddr, domain, qtype)
	}

	m := h.getMatcher()
	if m != nil {
		result := m.Match(domain)
		if h.Verbose {
			log.Printf("Domain: %s, Matched: %v", domain, result.Matched)
		}

		if result.Matched {
			fmt.Printf("[UDP] Blocking %s - returning NXDOMAIN\n", domain)
			nxdomainResponse := CreateNXDomainResponse(query)
			_, err := serverConn.WriteToUDP(nxdomainResponse, clientAddr)
			if err != nil {
				log.Printf("Failed to send NXDOMAIN response to client: %v", err)
			}
			return
		}
	}

	upstreamAddr, err := net.ResolveUDPAddr("udp", h.UpstreamDNS)
	if err != nil {
		log.Printf("Failed to resolve upstream DNS: %v", err)
		return
	}

	upstreamConn, err := net.DialUDP("udp", nil, upstreamAddr)
	if err != nil {
		log.Printf("Failed to connect to upstream DNS: %v", err)
		return
	}
	defer upstreamConn.Close()

	upstreamConn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err = upstreamConn.Write(query)
	if err != nil {
		log.Printf("Failed to send query to upstream: %v", err)
		return
	}

	if h.Verbose {
		log.Printf("Forwarded query to %s", h.UpstreamDNS)
	}

	responseBuffer := make([]byte, 512)
	n, err := upstreamConn.Read(responseBuffer)
	if err != nil {
		log.Printf("Failed to read response from upstream: %v", err)
		return
	}

	if h.Verbose {
		log.Printf("Received %d bytes from upstream", n)
	}

	_, err = serverConn.WriteToUDP(responseBuffer[:n], clientAddr)
	if err != nil {
		log.Printf("Failed to send response to client: %v", err)
		return
	}

	if h.Verbose {
		log.Printf("Sent response to %s", clientAddr)
	}
}

func (h *Handler) HandleTCP(clientConn net.Conn) {
	defer clientConn.Close()

	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))

	lengthBuf := make([]byte, 2)
	_, err := clientConn.Read(lengthBuf)
	if err != nil {
		log.Printf("Failed to read TCP length prefix: %v", err)
		return
	}

	queryLen := int(lengthBuf[0])<<8 | int(lengthBuf[1])
	if queryLen > 65535 {
		log.Printf("Invalid query length: %d", queryLen)
		return
	}

	query := make([]byte, queryLen)
	n, err := clientConn.Read(query)
	if err != nil {
		log.Printf("Failed to read TCP query: %v", err)
		return
	}

	if n != queryLen {
		log.Printf("Expected %d bytes but got %d", queryLen, n)
		return
	}

	domain, qtype := ParseQuery(query)
	if domain != "" {
		fmt.Printf("[TCP] %s -> %s (%s)\n", clientConn.RemoteAddr(), domain, qtype)
	}

	if h.Verbose {
		log.Printf("Processing TCP query from %s", clientConn.RemoteAddr())
	}

	m := h.getMatcher()
	if m != nil {
		result := m.Match(domain)
		if h.Verbose {
			log.Printf("Domain: %s, Matched: %v", domain, result.Matched)
		}

		if result.Matched {
			fmt.Printf("[TCP] Blocking %s - returning NXDOMAIN\n", domain)
			nxdomainResponse := CreateNXDomainResponse(query)
			responseLen := len(nxdomainResponse)
			lengthPrefix := []byte{byte(responseLen >> 8), byte(responseLen & 0xFF)}
			_, err := clientConn.Write(lengthPrefix)
			if err != nil {
				log.Printf("Failed to send NXDOMAIN length to client: %v", err)
				return
			}
			_, err = clientConn.Write(nxdomainResponse)
			if err != nil {
				log.Printf("Failed to send NXDOMAIN response to client: %v", err)
			}
			return
		}
	}

	upstreamConn, err := net.DialTimeout("tcp", h.UpstreamDNS, 5*time.Second)
	if err != nil {
		log.Printf("Failed to connect to upstream DNS via TCP: %v", err)
		return
	}
	defer upstreamConn.Close()

	upstreamConn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err = upstreamConn.Write(lengthBuf)
	if err != nil {
		log.Printf("Failed to send length prefix to upstream: %v", err)
		return
	}

	_, err = upstreamConn.Write(query)
	if err != nil {
		log.Printf("Failed to send query to upstream: %v", err)
		return
	}

	if h.Verbose {
		log.Printf("Forwarded TCP query to %s", h.UpstreamDNS)
	}

	responseLengthBuf := make([]byte, 2)
	_, err = upstreamConn.Read(responseLengthBuf)
	if err != nil {
		log.Printf("Failed to read response length from upstream: %v", err)
		return
	}

	responseLen := int(responseLengthBuf[0])<<8 | int(responseLengthBuf[1])

	response := make([]byte, responseLen)
	n, err = upstreamConn.Read(response)
	if err != nil {
		log.Printf("Failed to read response from upstream: %v", err)
		return
	}

	if h.Verbose {
		log.Printf("Received %d bytes from upstream via TCP", n)
	}

	_, err = clientConn.Write(responseLengthBuf)
	if err != nil {
		log.Printf("Failed to send response length to client: %v", err)
		return
	}

	_, err = clientConn.Write(response[:n])
	if err != nil {
		log.Printf("Failed to send response to client: %v", err)
		return
	}

	if h.Verbose {
		log.Printf("Sent TCP response to %s", clientConn.RemoteAddr())
	}
}
