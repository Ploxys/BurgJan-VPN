
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"math/rand"
	"time"
	"encoding/binary"
	"bytes"
	"strconv"
)

var (
	outIP          = "eyesergey.ru"
	serverPort     = 4446
	portLocalProxy = 3002
	login          = ""
	password       = ""
	outIP_FakeDNS  = "eyesergey.ru"
	ServerPort_fake	  = 8888
	metod = ""
	key = ""
	reserve_ip = "0"
	reserve_tls = 443
	reserve_dns = 53
	defence = ""
)

type AuthData struct {
	Who     string `json:"who"`
	Login   string `json:"login"`
	Password string `json:"password"`
	Key string `json:"key"`
	Port string `json:"port"`
	Host string `json:"host"`
}

func buildFakeHello() []byte {
	// Генерируем 32 случайных байта как TLS Random
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		log.Fatalf("Ошибка генерации random: %v", err)
	}

	// Собираем fake TLS Hello
	fakeHello := append([]byte{
		0x16, 0x03, 0x01, 0x00, 0x75, // Record Header
		0x01, 0x00, 0x00, 0x71,       // Handshake Header
		0x03, 0x03,                   // TLS 1.2
	}, randomBytes...) // Random

	fakeHello = append(fakeHello,
		0x00,                         // Session ID length
		0x00, 0x04, 0x00, 0x01, 0x00, 0x17, // Cipher Suites
		0x01, 0x00,                   // Compression
		0x00, 0x0f,                   // Extensions length
		0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, // Fake Extensions
	)

	return fakeHello
}
func buildDNSQuery(domain string) ([]byte, error) {
	var buf bytes.Buffer

	// ID транзакции
	id := uint16(rand.Intn(65535))
	binary.Write(&buf, binary.BigEndian, id)

	// Флаги: стандартный рекурсивный запрос 0x0100
	binary.Write(&buf, binary.BigEndian, uint16(0x0100))

	// Вопросов: 1
	binary.Write(&buf, binary.BigEndian, uint16(1))

	// Answer RRs, Authority RRs, Additional RRs: 0
	binary.Write(&buf, binary.BigEndian, uint16(0))
	binary.Write(&buf, binary.BigEndian, uint16(0))
	binary.Write(&buf, binary.BigEndian, uint16(0))

	// Вопрос (QNAME)
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		buf.WriteByte(byte(len(part)))
		buf.WriteString(part)
	}
	buf.WriteByte(0) // конец QNAME

	// QTYPE = 1 (A)
	binary.Write(&buf, binary.BigEndian, uint16(1))
	// QCLASS = 1 (IN)
	binary.Write(&buf, binary.BigEndian, uint16(1))

	return buf.Bytes(), nil
}
func handleSocksConnection(clientConn net.Conn) {
		buf := make([]byte, 262)
		_, err := io.ReadFull(clientConn, buf[:2]) // версия + количество методов
		if err != nil || buf[0] != 0x05 {
			log.Println("Bad SOCKS version")
			return
		}
		nMethods := int(buf[1])
		_, err = io.ReadFull(clientConn, buf[:nMethods])
		if err != nil {
			log.Println("Error reading methods")
			return
		}

		// Отвечаем: no auth
		clientConn.Write([]byte{0x05, 0x00})

		// ---------------------------
		// 2. SOCKS5: CONNECT request
		// ---------------------------
		_, err = io.ReadFull(clientConn, buf[:4]) // version, cmd, rsv, atyp
		if err != nil || buf[1] != 0x01 {
			log.Println("Only CONNECT supported")
			return
		}

		atyp := buf[3]
		var targetHost string
		switch atyp {
		case 0x01: // IPv4
			_, err = io.ReadFull(clientConn, buf[:4])
			targetHost = net.IP(buf[:4]).String()
		case 0x03: // Domain
			_, err = io.ReadFull(clientConn, buf[:1])
			addrLen := int(buf[0])
			_, err = io.ReadFull(clientConn, buf[:addrLen])
			targetHost = string(buf[:addrLen])
			fmt.Println(targetHost)
		case 0x04: // IPv6
			_, err = io.ReadFull(clientConn, buf[:16])
			targetHost = net.IP(buf[:16]).String()
			fmt.Println(targetHost)
		default:
			log.Println("Unsupported address type")
			return
		}
	// Чтение порта
		_, err = io.ReadFull(clientConn, buf[:2])
		targetPort := int(buf[0])<<8 | int(buf[1])
		log.Printf("→ SOCKS target: %s:%d\n", targetHost, targetPort)
		resp := make([]byte, 10)
    	resp[0] = 0x05          // VER
    	resp[1] = 0x00          // REP = succeeded
    	resp[2] = 0x00          // RSV
    	resp[3] = 0x01          // ATYP = IPv4

    	copy(resp[4:8], net.ParseIP(targetHost).To4()) // 4 байта IP

    	resp[8] = byte(targetPort >> 8) // старший байт порта
    	resp[9] = byte(targetPort & 0xff) // младший байт порта
    	_, err = clientConn.Write(resp)
		if metod == "DNS"{
				if defence == "Y" {
					go handleClient_fake_dns(clientConn,targetHost,strconv.Itoa(targetPort),reserve_ip, reserve_dns)
				} else{
					go handleClient_fake_dns(clientConn,targetHost,strconv.Itoa(targetPort),outIP_FakeDNS, ServerPort_fake)
				}
		}
		if metod == "TLS"{
				if defence == "Y"{
					go handleClient_obfs_tls(clientConn,targetHost,strconv.Itoa(targetPort), reserve_ip , reserve_tls)
				} else{
					go handleClient_obfs_tls(clientConn,targetHost,strconv.Itoa(targetPort), outIP, serverPort)
				}
			}
	}

func main() {
	fmt.Print("Порт локального прокси: ")
    fmt.Scan(&portLocalProxy)
	fmt.Print("login: ")
    fmt.Scan(&login)
	fmt.Print("password: ")
    fmt.Scan(&password)
	fmt.Print("Выберите маскировку DNS или TLS: ")
	fmt.Scan(&metod)
	defence = "N"
	fmt.Print("Выберите адрес сервера: ")
	fmt.Scan(&outIP)
	fmt.Print("Выберите порт сервера TLS: ")
	fmt.Scan(&serverPort)
	fmt.Print("Выберите порт сервера DNS: ")
	fmt.Scan(&ServerPort_fake)
	fmt.Print("|||Настройка завершена|||\n")
	key = randomString(1024)
	listen, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", portLocalProxy))
	if err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
	log.Printf("Proxy listening on 127.0.0.1:%d\n", portLocalProxy)
	for {
		for {
			clientConn, err := listen.Accept()
			if err != nil {
				log.Println("Ошибка при accept:", err)
				continue
			}

		go handleSocksConnection(clientConn) // Отдельная горутина

		}
	}
}
const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
func randomString(length int) string {
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func handleClient_fake_dns(clientConn net.Conn, host string, port string,outips string,outport int) {
	defer clientConn.Close()	
	rawConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", outips, outport))
	if err != nil {
    log.Println("Failed to dial:", err)
    return
	}
	fmt.Println("Имитируем DNS")
	quer, _ := buildDNSQuery("vk.com")
	_, err = rawConn.Write(quer)
	if err != nil {
		log.Fatal("Obfuscation write failed:", err)
	}
	buffer := make([]byte, 2048)
	n, err := rawConn.Read(buffer)
	if err != nil{
		log.Println("[!] Обмен obfs не удался")
		return
	}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "vk.com",
		NextProtos:         []string{"h2", "http/1.1"},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		MinVersion: tls.VersionTLS12,
	}

	conn := tls.Client(rawConn, tlsConfig)
	defer conn.Close()
	log.Println("[✓] Connected to server")

	// Авторизация
	auth := AuthData{"auth", login, password, key,port,host}
	authBytes, _ := json.Marshal(auth)
	_, err = conn.Write(authBytes)
	if err != nil {
		log.Println("Failed to send auth:", err)
		return
	}

	buffer = make([]byte, 2048)
	n, err = conn.Read(buffer)
	if err != nil || string(buffer[:n]) != "ok" {
		log.Println("[!] Авторизация не удалась")
		return
	}
	log.Println("[✓] Авторизация прошла")

	// 1. Отправляем адрес назначения
	//hostPort := host + ":" + port
	//_, err = conn.Write([]byte(hostPort))
	//if err != nil {
	//	log.Println("Failed to send target to server:", err)
	//	return
	//}

	// 2. Только теперь можно ответить клиенту (браузеру), что туннель готов
	//clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	// Двусторонняя пересылка
	go proxyPipe("клиент → сервер", clientConn, conn)
	proxyPipe("сервер → клиент", conn, clientConn)
}


func handleClient_obfs_tls(clientConn net.Conn, host string, port string,outips string,ports int) {
	defer clientConn.Close()
	rawConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", outips, ports))
	if err != nil {
    log.Println("Failed to dial:", err)
    return
	}
	if err != nil {
		log.Fatal("TCP connect error:", err)
	}

	// 2. Обфускация — отправка случайных байт ДО TLS
	obfs := buildFakeHello()
	fmt.Println("Sending obfuscation:", string(obfs))
	_, err = rawConn.Write(obfs)
	if err != nil {
		log.Fatal("Obfuscation write failed:", err)
	}
	buffer := make([]byte, 2048)
	n, err := rawConn.Read(buffer)
	if err != nil{
		log.Println("[!] Обмен obfs не удался")
		return
	}
	// TLS config without cert verification (for testing only!)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "vk.com", // SNI
		NextProtos:         []string{"h2", "http/1.1"},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		MinVersion: tls.VersionTLS12,
	}

	conn := tls.Client(rawConn, tlsConfig)
	defer conn.Close()
	log.Println("[✓] Connected to server")
	// Авторизация
	auth := AuthData{"auth", login, password,key,port,host}
	authBytes, _ := json.Marshal(auth)
	_, err = conn.Write(authBytes)
	if err != nil {
		log.Println("Failed to send auth:", err)
		return
	}

	buffer = make([]byte, 16000)
	n, err = conn.Read(buffer)
	if err != nil || string(buffer[:n]) != "ok" {
		log.Println("[!] Авторизация не удалась")
		return
	}
	log.Println("[✓] Авторизация прошла")
	// Ответ клиенту

	// Двусторонняя пересылка
	go proxyPipe("клиент → сервер", clientConn, conn)
	proxyPipe("сервер → клиент", conn, clientConn)
}

func proxyPipe(tag string, src net.Conn, dst net.Conn) {
    buf := make([]byte, 4096)
    for {
        n, err := src.Read(buf)
        if n > 0 {
            _, writeErr := dst.Write(buf[:n])
            if writeErr != nil {
                log.Printf("[%s] Write error: %v", tag, writeErr)
                return
            }
        }
        if err != nil {
            if err != io.EOF {
                log.Printf("[%s] Read error: %v", tag, err)
            }
            return
        }
    }
}
