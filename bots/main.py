import telebot 
import config
import db
bot = telebot.TeleBot(config.token)
@bot.message_handler(commands=['start'])
def start(message):
    try:
        config.admins.index(str(message.chat.id)) #Проверка админ ли
        bot.send_message(chat_id=message.chat.id,text=config.start_text)#реакция на команду старт
    except:
        pass #Если не админ игнорируем
#обработка команд
@bot.message_handler(content_types=["text"])
def handle_text(message):
    try:
        s = config.admins.index(str(message.chat.id))#поиск в списке админов если не найдено ошибка кидаем в except
        text = str(message.text).split(" ")
        itog = ""
        if text[0] == "help":
            bot.send_message(chat_id=message.chat.id,text=config.helpp)
        if text[0] == "adduser":
            itog = db.add_user(text[1],text[2],text[3])
            if itog != False:
                bot.send_message(chat_id=message.chat.id,text=itog)
            else:
                bot.send_message(chat_id=message.chat.id,text="🤯 Ошибка!\n\n🔎 Перепроверьте запрос")
        if text[0] == "ban":
            itog = db.ban(text[1])
            bot.send_message(chat_id=message.chat.id,text=itog)
        if text[0] == "users":
            itog = db.static()
            bot.send_message(chat_id=message.chat.id,text="🔒 Активные пользовтели TLS: " + str(itog[0]) + "\n🌐 Активные пользовтели DNS:" + str(itog[1]) + "\n🫡 Число регистраций: " + str(itog[2]))
        if text[0] == "limit":
            itog = db.set_limit(text[1],text[2])
            bot.send_message(chat_id=message.chat.id,text=itog)
        if text[0] == "user":
            itog = db.user_get(text[1])
            bot.send_message(chat_id=message.chat.id,text=itog)
        if text[0] == "workload":
            db.work_servers(message.chat.id,bot)
    except:
        bot.send_message(chat_id=message.chat.id,text="Ошибка")
bot.polling(none_stop=True)