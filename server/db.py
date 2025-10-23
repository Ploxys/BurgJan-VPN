from pymongo import MongoClient
import json
import http.client
import psutil
import time
import datetime
client = MongoClient('127.0.0.1:27017')
db = client['BurgJan']
user = db.login
servers = db.servers
def search(js,proto):
    js = json.loads(js)
    #print(js)
    request = user.find_one({"login": js["login"],"password": js["password"]})
    #print(request)
    if request != None:
        add_data_user_date(js["login"],proto)
        return js
    return False

def search_limit(login):
    request = user.find_one({"login": str(login)})
    if request != None:
        return int(request["limit"])
    return 0

def get_network_load():
    net_io = psutil.net_io_counters()
    bytes_sent = net_io.bytes_sent
    bytes_recv = net_io.bytes_recv
    time.sleep(1)  # Подождать секунду
    net_io_2 = psutil.net_io_counters()
    bytes_sent_2 = net_io_2.bytes_sent
    bytes_recv_2 = net_io_2.bytes_recv
    
    sent_speed = (bytes_sent_2 - bytes_sent)
    recv_speed = (bytes_recv_2 - bytes_recv)
    
    return sent_speed, recv_speed

def add_data_user_date(login,proto):
    if user.find_one({"login": login}) != None and proto == "TLS":
        result = db.login.update_many({'login': login},
                {'$set': {'TLS': str(datetime.datetime.now().date())}})
    if user.find_one({"login": login}) != None and proto == "DNS":
        result = db.login.update_many({'login': login},
                {'$set': {'DNS': str(datetime.datetime.now().date())}})

def get_max(login):
    s = user.find_one({"login": login})
    if s != None:
        return s["limit"]

def add_data_users_tls(users,host):
    sent, received = get_network_load()
    mem = psutil.virtual_memory()
    cpu_percent = psutil.cpu_percent(interval=1)
    f = servers.find_one({"ip": host})
    if f != None:
        result = db.servers.update_many({'ip': host},
                {'$set': {'TLS': users,
                "ip": host,
                "cpu": cpu_percent,
                "RAM": round(mem.used / 1073741824),
                "RAMfree": round(mem.free / 1073741824),
                "recive": round(sent / 1024 / 1024),
                "send": round(received/ 1024 / 1024),
                "TLS": users,
                "DNS": f["DNS"]}})
    else:
        globalis = {
        "ip": host,
        "cpu": cpu_percent,
        "RAM": round(mem.used / 1073741824),
        "RAMfree": round(mem.free / 1073741824),
        "recive": round(sent / 1024 / 1024),
        "send": round(received/ 1024 / 1024),
        "TLS": users,
        "DNS": 0}
        post_id = servers.insert_one(globalis).inserted_id

def auth_add(login,serv):
    if user.find_one({"login": login}) != None:
        result = db.login.update_many({'login': login},
                {'$set': {'last_server': serv}})

def add_data_users_dns(users,host):
    sent, received = get_network_load()
    mem = psutil.virtual_memory()
    cpu_percent = psutil.cpu_percent(interval=1)
    f = servers.find_one({"ip": host})
    if f != None:
        result = db.servers.update_many({'ip': host},
                {'$set': {'TLS': users,
                "ip": host,
                "cpu": cpu_percent,
                "RAM": round(mem.used / 1073741824),
                "RAMfree": round(mem.free / 1073741824),
                "recive": round(sent / 1024 / 1024),
                "send": round(received/ 1024 / 1024),
                "TLS": f["TLS"],
                "DNS": users}})
    else:
        globalis = {
        "ip": host,
        "cpu": cpu_percent,
        "RAM": round(mem.used / 1073741824),
        "RAMfree": round(mem.free / 1073741824),
        "recive": round(sent / 1024 / 1024),
        "send": round(received/ 1024 / 1024),
        "TLS": 0,
        "DNS": users}
        post_id = servers.insert_one(globalis).inserted_id