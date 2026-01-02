package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

var (
	UUID        = getEnv("UUID", "b64c9a01-3f09-4dea-a0f1-dc85e5a3ac19")
	DOMAIN      = getEnv("DOMAIN", "1234.abc.com")
	SUB_PATH    = getEnv("SUB_PATH", "dc85e5a3ac19/sub")
	NAME        = getEnv("NAME", "katabump")
	PORT        = getEnvInt("PORT", 20102)
	AUTO_ACCESS = getEnvBool("AUTO_ACCESS", false)

	ISP         = "Unknown"
	DNS_SERVERS = []string{"8.8.4.4", "1.1.1.1"}
)

func getEnv(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return def
}

func getEnvInt(key string, def int) int {
	if val := os.Getenv(key); val != "" {
		var i int
		fmt.Sscanf(val, "%d", &i)
		return i
	}
	return def
}

func getEnvBool(key string, def bool) bool {
	if val := os.Getenv(key); val != "" {
		return val == "true" || val == "1"
	}
	return def
}

// ---------------- ISP 查询 ----------------
func GetISP() {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.ip.sb/geoip")
	if err != nil {
		ISP = "Unknown"
		return
	}
	defer resp.Body.Close()
	var data struct {
		CountryCode string `json:"country_code"`
		ISP         string `json:"isp"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		ISP = "Unknown"
		return
	}
	ISP = fmt.Sprintf("%s-%s", data.CountryCode, strings.ReplaceAll(data.ISP, " ", "_"))
}

// ---------------- 自定义 DNS ----------------
func resolveHost(host string) (string, error) {
	if net.ParseIP(host) != nil {
		return host, nil
	}
	ips, err := net.LookupIP(host)
	if err == nil && len(ips) > 0 {
		return ips[0].String(), nil
	}
	// HTTP DNS fallback
	for _, _ = range DNS_SERVERS {
		url := fmt.Sprintf("https://dns.google/resolve?name=%s&type=A", host)
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		var result struct {
			Status int `json:"Status"`
			Answer []struct {
				Type int    `json:"type"`
				Data string `json:"data"`
			} `json:"Answer"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()
		if result.Status == 0 && len(result.Answer) > 0 {
			for _, ans := range result.Answer {
				if ans.Type == 1 {
					return ans.Data, nil
				}
			}
		}
	}
	return "", fmt.Errorf("failed to resolve %s", host)
}

// ---------------- HTTP 订阅 ----------------
func subscribeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("This is a Discord bot endpoint. Access denied."))
		return
	}
	if r.URL.Path != "/"+SUB_PATH {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found\n"))
		return
	}

	namePart := fmt.Sprintf("%s-%s", NAME, ISP)
	wToken := UUID[:8]
	WSPATH := fmt.Sprintf("api/v1/user?token=%s&lang=en", wToken)
	vlessURL := fmt.Sprintf("vless://%s@cdns.doon.eu.org:443?encryption=none&security=tls&sni=%s&fp=firefox&type=ws&host=%s&path=%%2F%s#%s",
		UUID, DOMAIN, DOMAIN, WSPATH, namePart)
	trojanURL := fmt.Sprintf("trojan://%s@cdns.doon.eu.org:443?security=tls&sni=%s&fp=firefox&type=ws&host=%s&path=%%2F%s#%s",
		UUID, DOMAIN, DOMAIN, WSPATH, namePart)
	subscription := vlessURL + "\n" + trojanURL
	encoded := base64.StdEncoding.EncodeToString([]byte(subscription))
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(encoded + "\n"))
}

// ---------------- WebSocket 协议处理 ----------------
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	_, msg, err := ws.ReadMessage()
	if err != nil {
		return
	}

	uuidBytes, _ := hex.DecodeString(strings.ReplaceAll(UUID, "-", ""))
	if len(msg) > 17 && msg[0] == 0 && bytes.Equal(msg[1:17], uuidBytes) {
		handleVlessConnection(ws, msg)
		return
	}

	if !handleTrojanConnection(ws, msg) {
		ws.Close()
	}
}

// ---------------- VLESS 转发 ----------------
func handleVlessConnection(ws *websocket.Conn, msg []byte) {
	i := int(msg[17]) + 19
	if i+2 > len(msg) {
		ws.Close()
		return
	}
	port := int(msg[i])<<8 | int(msg[i+1])
	i += 2
	atyp := msg[i]
	i++

	var host string
	switch atyp {
	case 1:
		if i+4 > len(msg) {
			ws.Close()
			return
		}
		host = fmt.Sprintf("%d.%d.%d.%d", msg[i], msg[i+1], msg[i+2], msg[i+3])
		i += 4
	case 3:
		if i >= len(msg) {
			ws.Close()
			return
		}
		l := int(msg[i])
		i++
		if i+l > len(msg) {
			ws.Close()
			return
		}
		host = string(msg[i : i+l])
		i += l
	default:
		ws.Close()
		return
	}

	duplex := make(chan struct{})
	go func() {
		ip, err := resolveHost(host)
		if err != nil {
			ip = host
		}
		conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ip, port))
		if err != nil {
			ws.Close()
			return
		}
		defer conn.Close()

		if i < len(msg) {
			conn.Write(msg[i:])
		}

		go func() { io.Copy(conn, websocketReader(ws)) }()
		io.Copy(websocketWriter(ws), conn)
		close(duplex)
	}()
	<-duplex
}

// ---------------- Trojan 转发 ----------------
func handleTrojanConnection(ws *websocket.Conn, msg []byte) bool {
	if len(msg) < 58 {
		return false
	}
	recvHash := string(msg[:56])
	hash := sha256.Sum224([]byte(UUID))
	if hex.EncodeToString(hash[:]) != recvHash {
		return false
	}
	offset := 56
	if msg[offset] == 0x0d && msg[offset+1] == 0x0a {
		offset += 2
	}
	if offset >= len(msg) || msg[offset] != 0x01 {
		return false
	}
	offset += 1
	atyp := msg[offset]
	offset += 1
	var host string
	var port int
	switch atyp {
	case 1:
		if offset+4 > len(msg) {
			return false
		}
		host = fmt.Sprintf("%d.%d.%d.%d", msg[offset], msg[offset+1], msg[offset+2], msg[offset+3])
		offset += 4
	case 3:
		l := int(msg[offset])
		offset++
		if offset+l > len(msg) {
			return false
		}
		host = string(msg[offset : offset+l])
		offset += l
	default:
		return false
	}
	if offset+2 > len(msg) {
		return false
	}
	port = int(msg[offset])<<8 | int(msg[offset+1])
	offset += 2

	if offset+2 <= len(msg) && msg[offset] == 0x0d && msg[offset+1] == 0x0a {
		offset += 2
	}

	go func() {
		ip, err := resolveHost(host)
		if err != nil {
			ip = host
		}
		conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ip, port))
		if err != nil {
			ws.Close()
			return
		}
		defer conn.Close()

		if offset < len(msg) {
			conn.Write(msg[offset:])
		}

		go func() { io.Copy(conn, websocketReader(ws)) }()
		io.Copy(websocketWriter(ws), conn)
	}()
	return true
}

// ---------------- WS 读写转换 ----------------
func websocketReader(ws *websocket.Conn) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		for {
			_, msg, err := ws.ReadMessage()
			if err != nil {
				return
			}
			pw.Write(msg)
		}
	}()
	return pr
}

func websocketWriter(ws *websocket.Conn) io.Writer {
	pr, pw := io.Pipe()
	go func() {
		defer ws.Close()
		buf := make([]byte, 4096)
		for {
			n, err := pr.Read(buf)
			if err != nil {
				return
			}
			ws.WriteMessage(websocket.BinaryMessage, buf[:n])
		}
	}()
	return pw
}

// ---------------- main ----------------
func main() {
	GetISP()
	http.HandleFunc("/", subscribeHandler)
	http.HandleFunc("/"+SUB_PATH, subscribeHandler)
	http.HandleFunc("/ws", wsHandler)

	addr := fmt.Sprintf(":%d", PORT)
	fmt.Printf("Bot interaction server running on port %d\n", PORT)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Println("Server error:", err)
	}
}
