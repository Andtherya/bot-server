package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
)

// ---------------- 环境变量 ----------------
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
var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

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
	if len(msg) > 17 && msg[0] == 0 && string(msg[1:17]) == string(uuidBytes) {
		handleVless(ws, msg)
		return
	}

	if !handleTrojan(ws, msg) {
		ws.Close()
	}
}

// ---------------- VLESS 转发 ----------------
func handleVless(ws *websocket.Conn, msg []byte) {
	if len(msg) < 19 {
		ws.Close()
		return
	}
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

	go wsTCPForward(ws, host, port, msg[i:])
}

// ---------------- Trojan 转发 ----------------
func handleTrojan(ws *websocket.Conn, msg []byte) bool {
	if len(msg) < 58 {
		return false
	}
	hash := sha256.Sum224([]byte(UUID))
	if string(hex.EncodeToString(hash[:])) != string(msg[:56]) {
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

	go wsTCPForward(ws, host, port, msg[offset:])
	return true
}

// ---------------- TCP ↔ WS 转发 ----------------
func wsTCPForward(ws *websocket.Conn, host string, port int, firstPayload []byte) {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		ws.Close()
		return
	}
	defer conn.Close()

	// 发送第一个 payload
	if len(firstPayload) > 0 {
		conn.Write(firstPayload)
	}

	// TCP -> WS
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				ws.Close()
				return
			}
			ws.WriteMessage(websocket.BinaryMessage, buf[:n])
		}
	}()

	// WS -> TCP
	buf := make([]byte, 4096)
	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			conn.Close()
			return
		}
		conn.Write(msg)
	}
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
