HOST = "0.0.0.0"
PORT = 8080

class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        html = """
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <title>Факт дня</title>
        </head>
        <body>
            <h1>🐙 Факт дня</h1>
            <p>Осьминоги имеют три сердца и голубую кровь.</p>
        </body>
        </html>
        """
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html.encode("utf-8"))))
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

if __name__ == "__main__":
    with HTTPServer((HOST, PORT), MyHandler) as server:
        print(f"Сервер запущен: http://{HOST}:{PORT}")
        server.serve_forever()