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
import secrets
import string
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
        self.fake_sni = b"vk.com" 
        # Настройки безопасности
        self.context.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_COMPRESSION)
        self.context.set_cipher_list(
        b'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:'
        b'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384'
        )        
        # Callback для обработки ClientHello
        self.context.set_info_callback(self._ssl_info_callback)
    def wrap_http(self,payload):
        # приводим в bytes, если передали str
        if isinstance(payload, str):
            payload = payload.encode('utf-8')
        if payload is None:
            payload = b''

        headers = (
            b"POST / HTTP/1.1\r\n"
            b"Host: vk.com\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Length: " + str(len(payload)).encode('ascii') + b"\r\n\r\n"
        )
        return headers + payload

    def _add_dummy_extensions(self, conn):
            """Добавление фальшивых расширений"""
            # Используем ctypes для доступа к низкоуровневым функциям OpenSSL
            from ctypes import CDLL, c_void_p, c_uint, POINTER
            libssl = CDLL("libssl.so.1.1")
            
            # Добавляем фальшивое расширение
            ssl_p = c_void_p(id(conn._ssl))
            ext_type = 0x5a5a  # Кастомный тип расширения
            ext_data = b"\x01\x02\x03\x04"  # Произвольные данные
            
            libssl.SSL_add_clienthello_use_srtp_ext.argtypes = [c_void_p, c_uint, c_void_p, c_uint]
            libssl.SSL_add_clienthello_use_srtp_ext(ssl_p, ext_type, ext_data, len(ext_data))
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
    def cleaner(self,key,conn,login):
        with self.clients_lock:
            if key in self.clients:
                connections = self.clients[key]
                limit = db.search_limit(login)
                if len(connections) > limit:
                    print("Достигнут люмит: " +  str(limit) + " сейчас я хорошо почистю уберу: " + login)
                    for c in connections:
                            if c["conn"] != conn:
                                try:
                                    self.clients[key].remove(c["conn"])
                                except:
                                    pass
                                try:
                                    c["conn"].shutdown()
                                except:
                                    pass
                                try:
                                    c["conn"].close()
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
                    w = Thread(target=self.wanish_two,args=(),daemon = True)
                    w.start()
                    #print(2)
                    self.on = 1
            if auth_status == False:
                if not data:
                    conn.close()
                    #print(auth_status)
                if auth_status == False:
                    auth_status = self.auth(str(data.decode("utf-8")))
                    #print(auth_status)
                    if auth_status != False:
                        self.tokens.append(auth_status["key"])
                        w = Thread(target=self.cleaner,args=(auth_status["key"],conn,auth_status["login"]),daemon = True)
                        w.start()
                        conn.send("ok".encode("utf-8"))
                        self.clients.setdefault(auth_status["key"], []).append({
                        "conn": conn,
                        "login": auth_status["login"]
                        })
                        self.wait_for_disconnect(conn,addr,auth_status["key"],auth_status["port"],auth_status["host"])
                    else:
                        conn.close()
                else:
                    w = Thread(target=self.cleaner,args=(auth_status["key"],conn,auth_status["login"]),daemon = True)
                    w.start()
                    self.clients.setdefault(auth_status["key"], []).append({
                        "conn": conn,
                        "login": auth_status["login"]
                        })
                    self.wait_for_disconnect(conn,addr,auth_status["key"],auth_status["port"],auth_status["host"])

        except Exception as e:
            #print(e)
            try:
                conn.shutdown()
            except:
                pass
            try:
                conn.close()
            except:
                pass
            return
    def auth(self,js):
        return db.search(js,"TLS")
    def wait_for_disconnect(self, client_sock,addr,key,port,host):
        datas = None
        bom = 0
        #print(ip,port)
        #os.system('cls' if os.name == 'nt' else 'clear')
        #print(f"[INFO] Количество клиентов: {len(self.clients)}")
        #print(f"[TLS] Новое соединение от {addr}")
        while True:
            try:
                data = client_sock.recv(24000)
                #print(data)
                obrabot.main(client_sock,data,host,port)
            except Exception as e:
                try:
                    client_sock.shutdown()
                except:
                    pass
                try:
                    client_sock.close()
                except:
                    pass
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
        sock = socket(AF_INET, SOCK_STREAM)
        sock.bind((self.host, self.port))
        sock.listen(24000)
        self.running = True
        print(f"Server started on {self.host}:{self.port}")
        #try:
        while self.running:
                try:
                    client_sock, addr = sock.accept()
                    #print(addr)
                    #try:
                    pre_tls_data = client_sock.recv(1024)
                    #print(pre_tls_data)
                    s = ""
                    try:
                        s = pre_tls_data.decode("utf-8")
                    except:
                        pass
                    #print(pre_tls_data)
                    #print(pre_tls_data)
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
                        alphabet = string.ascii_letters + string.digits
                        password = ''.join(secrets.choice(alphabet) for i in range(20))  # for a 20-character password
                        client_sock.send(self.wrap_http(password))
                        #print(pre_tls_data)
                        #print(f"[DEBUG] Обфускация: {pre_tls_data[:16]}...")  # можно убрать
                    #except Exception as e:
                        #print(e)
                        #rint(f"[ERROR] Не удалось прочитать обфускацию: {e}")
                        #client_sock.close()
                        #continue
                    ssl_conn = SSL.Connection(self.context, client_sock)
                    ssl_conn.set_accept_state()
                    # Запускаем обработку в отдельном потоке
                    
                    client_thread = Thread(target=self._handle_client, args=(ssl_conn, addr))

                    client_thread.daemon = True
                    client_thread.start()
                except Exception as e:
                    print(e)
                    try:
                        ssl_conn.shutdown()
                    except:
                        pass
                    try:
                        ssl_conn.close()
                    except:
                        pass
                    #print(f"Accept error: {e}")
        #finally:
        #    sock.close()
        #    #print("Server stopped")
    
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


    def wanish_two(self):
        while 1:
            try:
                alive_clients = {}
                time.sleep(2)
                for token, conns in self.clients.items():
                    #os.system('cls' if os.name == 'nt' else 'clear')
                    #print(f"Клиентов: " +  str({len(token)}))
                    for sock in conns:
                        try:
                            #sock["conn"].send(b'hmmm')
                            # select на чтение с таймаутом 0 — не блокирует
                            r, _, e = select.select([sock["conn"]], [], [sock["conn"]], 0)

                           # если сокет не в ошибке и не закрыт
                            if sock["conn"] in e:
                               raise Exception("Сокет в ошибке")
                            if sock["conn"].fileno() == -1:
                                raise Exception("Сокет уже закрыт")

                        except Exception as e:
                            #print("[" + str(datetime.now().strftime("%d.%m.%Y %H:%M:%S")) + "] [" + "wanish_two" + " ] " + str(e))

                            try:
                                sock["conn"].shutdown()
                            except Exception as e:pass
                                #print("[" + str(datetime.now().strftime("%d.%m.%Y %H:%M:%S")) + "] [" + "Wanish_two " + " ] " + str(e))

                            try:
                                sock["conn"].close()
                            except Exception as e:
                                pass
                                #print("[" + str(datetime.now().strftime("%d.%m.%Y %H:%M:%S")) + "] [" + "Wanish_two " + " ] " + str(e))
                            try:
                                self.clients[token].remove(sock["conn"])
                            except:pass
            except:
                pass        #print("[" + str(datetime.now().strftime("%d.%m.%Y %H:%M:%S")) + "] [" + "Wanish_two " + " ] " + str(e))                        
       



if __name__ == "__main__":
    server = OpenSSLServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
