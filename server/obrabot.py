from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
def forward(src, dst, tag):
    try:
        while True:
            #print("dooone")
            data = src.recv(16000)
            if not data:
                #print(f"[{tag}] Соединение закрыто")
                try:
                    dst.shutdown()
                except:
                    pass
                break
            dst.sendall(data)
            #print("done")
    except Exception as e:
        try:
            sockk.shutdown(2)
        except: pass
        try:
            sockk.close()
        except: pass
        try:
            remote.shutdown(2)
        except: pass
        try:
            remote.close()
        except: pass
def main(sockk, data, FORWARD_HOST, FORWARD_PORT):
    remote = socket(AF_INET, SOCK_STREAM)
    try:
        target_host = str(FORWARD_HOST)
        target_port = int(FORWARD_PORT)
        #print(target_host)
        request_raw = data  # bytes, без декодирования
        # Попытка получить порт из parts[2], если невалидно - ставим дефолт

        #print(f"[+] Подключаемся к {target_host}:{target_port}")
        remote.connect((target_host, target_port))
        remote.send(data)
        t1 = Thread(target=forward, args=(sockk, remote, "клиент → сервер"))
        t2 = Thread(target=forward, args=(remote, sockk, "сервер → клиент"))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    except Exception as e:
        print(f"[obrabot] Ошибка: {e}")
        try:
            sockk.shutdown()
            remote.shutdown()
        except:
            pass
