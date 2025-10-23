from pymongo import MongoClient
import json
import datetime
client = MongoClient('127.0.0.1:27017')
db = client['BurgJan']
user = db.login
server = db.servers
def add_user(users,password,limit):
    request = user.find_one({"login": users,"password": password})
    if request != None:
        return False
    globalis = {
        "login": users,
        "password": password,
        "limit": int(limit),
        "DNS": "None",
        "TLS": "None",
        "registration": str(datetime.datetime.now().date()),
        "last_server": "None"}
    post_id = user.insert_one(globalis).inserted_id
    add_user_response = "👨‍🦰 Пользователь: " + users + "\n🔐 Пароль: " + password +"\n😎 Люмит: " + str(limit) + "\n\n😉 Успешно создан и готов к работе"
    return add_user_response
def ban(users):
    request = user.find_one({"login": users})
    if request != None:
        db.login.delete_one({"login": users})
        return "🧑‍⚖️ Пользователь заблокирован"
    else:
        return "🔎 Пользователь не найден "

def static():
    total_documents = user.count_documents({})
    users_TLS = 0
    users_DNS = 0
    request = server.find({})
    for r in request:
        users_TLS = users_TLS + r["TLS"]
        users_DNS = users_DNS + r["DNS"]
    return users_TLS,users_DNS,total_documents


def set_limit(users,limit):
    if user.find_one({"login": users}) != None:
        result = db.login.update_many({'login': users},
                {'$set': {'limit': int(limit)}})
        return "✅ Люмит изменен на " + limit + " соеденений"
    else:
        return "⚠️ Люмит не удалось поменять пользователь не найден"
    
def user_get(login):
    users = user.find_one({"login": login})
    if users != None:
        return "Пользователь: " + login + "\n🔒Пароль: " + users["password"] + "\n⛔️ Люмит: " + str(users["limit"]) + "\n\n🛡 Подключение к DNS: " + users["DNS"] + "\n🛡 Подключение к TLS: " +  users["TLS"] +"\n\n💻 Последний сервер: " + users["last_server"] +"\n✍️ Регистрация: " + users["registration"]
    else:
        return "🤷‍♂️ Пользователь не найден"

def work_servers(chat_id,bot):
    servers = server.find({})
    for serv in servers:
        info =  "🏚 IP: " + str(serv["ip"]) +"\n🧠 Процессор: " + str(serv["cpu"]) + "%" + "\n🤯 Оперативка занято: " + str(serv["RAM"]) + " ГБ" + "\n🕊 Оперативка свободно: " + str(serv["RAMfree"]) + " ГБ" +"\n📶 Сеть прием: " + str(serv["recive"]) + "\n📶 Сеть отдача: " + str(serv["send"]) + "\n🥇TLS users: " + str(serv["TLS"]) + "\n🥈DNS users: " + str(serv["DNS"])
        bot.send_message(chat_id=chat_id,text=info)