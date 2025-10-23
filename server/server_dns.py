from OpenSSL import SSL, crypto
from socket import socket, AF_INET, SOCK_STREAM,SOL_SOCKET,IPPROTO_TCP,SO_KEEPALIVE,TCP_KEEPIDLE,TCP_KEEPINTVL,TCP_KEEPCNT
from threading import Thread
import os
import time
import db
import asyncio
import obrabot
import random
import os 
from threading import Lock
import select
port_server = int(input("server port: "))
class OpenSSLServer:
    def __init__(self, host='0.0.0.0', port=port_server):
        self.host = host
        self.port = port
        self.tokens = []
        self.context = None
        self.running = False
        self.iptables_lock = Lock()
        self.iptables = {}
        self.keys_lock = Lock()
        self.keys = {}
        self.max_connections_per_ip = 100
        # Инициализация SSL контекста
        self._init_ssl_context()

    def _init_ssl_context(self):
        self.on = 0
        self.clients = {}
        self.clients_lock = Lock()
        """Инициализация SSL контекста с настройками"""
        self.context = SSL.Context(SSL.TLSv1_2_METHOD)
        
        # Загрузка сертификатов
        self.context.set_alpn_protos([b'h2', b'http/1.1'])
        self.context.use_privatekey_file('sec/server.key')
        self.context.use_certificate_file('sec/server.crt')
        self.fake_sni = b"kremlin.ru" 
        # Настройки безопасности
        self.context.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_COMPRESSION)
        self.context.set_cipher_list(
        b'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:'
        b'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384'
        )        
        # Callback для обработки ClientHello
        self.context.set_info_callback(self._ssl_info_callback)


    def _ssl_info_callback(self, conn, where, ret):
        """Callback для обработки событий SSL"""
        if where & SSL.SSL_CB_HANDSHAKE_START:
            pass
            #print("Handshake started")

        if where & SSL.SSL_CB_HANDSHAKE_DONE:
            pass
            #print("Handshake completed")
            #print("Selected cipher:", conn.get_cipher_name())
            #print("Client SNI:", conn.get_servername())
    def cleaner(self,key,conn):
        with self.clients_lock:
            for token, conns in self.clients.items():
                if len(conns) > self.max_connections_per_ip:
                        for c in conns:
                            if c != conn:
                                try:
                                    self.clients[key].remove(c)
                                except:
                                    pass
                                try:
                                    c.close()
                                except:
                                    pass
                            
    def _handle_client(self, conn, addr):
        try:
            data = conn.recv(24000)
            if not data:
                conn.close()
                return
            auth_status = False
            if self.on == 0:
                    wani = Thread(target=self.wanish,args=(),daemon = True)
                    wani.start()
                    #w = Thread(target=self.wanish_two,args=(),daemon = True)
                    #w.start()
                    #print(2)
                    self.on = 1
            if auth_status == False:
                if not data:
                    conn.close()
                    #print(auth_status)
                if auth_status == False:
                    auth_status = self.auth(str(data.decode("utf-8")))
                    print(auth_status)
                    if auth_status != False:
                        self.tokens.append(auth_status["key"])
                        w = Thread(target=self.cleaner,args=(auth_status["key"],conn),daemon = True)
                        w.start()
                        conn.send("ok".encode("utf-8"))
                        self.clients.setdefault(auth_status["key"], []).append(conn)
                        self.wait_for_disconnect(conn,addr,auth_status["key"],auth_status["port"],auth_status["host"])
                    else:
                        conn.close()
                else:
                    w = Thread(target=self.cleaner,args=(auth_status["key"],conn),daemon = True)
                    w.start()
                    self.clients.setdefault(auth_status["key"], []).append(conn)
                    self.wait_for_disconnect(conn,addr,auth_status["key"],auth_status["port"],auth_status["host"])

        except Exception as e:
            #print(e)
            conn.close()
            return
    def auth(self,js):
        return db.search(js,"DNS")
    def wait_for_disconnect(self, client_sock,addr,key,port,host):
        datas = None
        bom = 0
        #print(ip,port)
        #os.system('cls' if os.name == 'nt' else 'clear')
        #print(f"[INFO] Количество клиентов: {len(self.clients)}")
        #print(f"[TLS] Новое соединение от {addr}")
        while True:
            #try:
                data = client_sock.recv(24000)
                #print(data)
                obrabot.main(client_sock,data,host,port)
            #except Exception as e:
            #    #print(f"[!] Ошибка соединения: {e}")
            #    with self.clients_lock:
            #        try:
            #            self.clients[key].remove(client_sock)
            #        except:
            #            pass
            #    client_sock.close()
            #    break
    def start(self):
        """Запуск сервера"""
        after_idle_sec = 60
        interval_sec = 10
        max_fails = 5
        sock = socket(AF_INET, SOCK_STREAM)
        sock.bind((self.host, self.port))
        sock.listen(24000)
        self.running = True
        #print(f"Server started on {self.host}:{self.port}")
        try:
            while self.running:
                try:
                    client_sock, addr = sock.accept()
                    client_sock.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)
                    client_sock.setsockopt(IPPROTO_TCP, TCP_KEEPIDLE, after_idle_sec)
                    client_sock.setsockopt(IPPROTO_TCP, TCP_KEEPINTVL, interval_sec)
                    client_sock.setsockopt(IPPROTO_TCP, TCP_KEEPCNT, max_fails)
                    try:
                        pre_tls_data = client_sock.recv(24000)
                        s = ""
                        try:
                            s = pre_tls_data.decode("utf-8")
                        except:
                            pass
                        if s.find("HTTP/1.1") != -1:
                            #print("done")
                            with open("fake_http/fake.html", "r", encoding="utf-8") as file:
                                content = file.read()
                                response = (
                            "HTTP/1.1 200 OK\r\n"
                            "Content-Type: text/html; charset=utf-8\r\n"
                            f"Content-Length: {len(content.encode('utf-8'))}\r\n"
                            "\r\n"  # Пустая строка отделяет заголовки от тела
                                + content
                                )

                            client_sock.send(response.encode("utf-8"))
                            client_sock.close()
                            continue
                        else:
                            client_sock.send(b'169 115 129 128 0 1 0 6 0 0 0 0 2 118 107 3 99 111 109 0 0 1 0 1 192 12 0 1 0 1 0 0 1 30 0 4 87 240 129 133 192 12 0 1 0 1 0 0 1 30 0 4 87 240 132 78 192 12 0 1 0 1 0 0 1 30 0 4 87 240 132 72 192 12 0 1 0 1 0 0 1 30 0 4 87 240 132 67 192 12 0 1 0 1 0 0 1 30 0 4 93 186 225 194 192 12 0 1 0 1 0 0 1 30 0 4 87 240 137 164')
                            #print(pre_tls_data)
                            #print(f"[DEBUG] Обфускация: {pre_tls_data[:16]}...")  # можно убрать
                    except Exception as e:
                        #print(e)
                        #rint(f"[ERROR] Не удалось прочитать обфускацию: {e}")
                        client_sock.close()
                        continue
                    ssl_conn = SSL.Connection(self.context, client_sock)
                    ssl_conn.set_accept_state()
                    # Запускаем обработку в отдельном потоке
                    
                    client_thread = Thread(target=self._handle_client, args=(ssl_conn, addr))

                    client_thread.daemon = True
                    client_thread.start()
                except Exception as e:
                    print(f"Accept error: {e}")
        finally:
            sock.close()
            #print("Server stopped")
    
    def stop(self):
        """Остановка сервера"""
        self.running = False


    def wanish(self):
        while 1:
            time.sleep(5)
            #os.system('cls' if os.name == 'nt' else 'clear')
            unique = self.tokens[0:0]
            for i in range(len(self.tokens)):
                if self.tokens[i] in unique: 
                    continue
                unique.append(self.tokens[i])
            #print("Число пользователей: " + str(len(unique)))


    #def wanish_two(self):
    #    while 1:
    #        alive_clients = {}
    #        time.sleep(5)
    #        for token, conns in self.clients.items():
    #            #os.system('cls' if os.name == 'nt' else 'clear')
    #            #print(f"Клиентов: " +  str({len(token)}))
    #            for sock in conns:
    #                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    #                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, after_idle_sec)
    #                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval_sec)
    #                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, max_fails)
    #                except Exception as e:
    #                    print(f"[wanish] Удаляю мёртвый сокет: {e}")
    #                    try:
    #                        self.clients[token].remove(sock)
    #                    except:
    #                        pass
    #                    try:
    #                        sock.shutdown(socket.SHUT_RDWR)
    #                    except:
    #                        pass
    #                    try:
    #                        sock.close()
    #                    except:
    #                        pass
                        



if __name__ == "__main__":
    server = OpenSSLServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()

