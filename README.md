# BurgJan

## **A proxy server–client resistant to blocking**

⸻

## 🧩 Overview

BurgJan achieves resilience by fully imitating HTTPS traffic and DNS requests.

By default, DNS queries are spoofed to look like requests to VKontakte, but you can easily change this in the client and server code.

### ⚙️ In the future, this will be configurable via commands (currently in development).

⸻

## 🚀 How It Works

The client sends a request to the server that looks like a regular HTTP connection, which then transitions into TLS.
The DPI (Deep Packet Inspection) system assumes it’s a normal encrypted connection.
A fake website (which you can customize) is attached to the same port where BurgJan runs, further increasing the disguise level of the tunnel.

## DNS Obfuscation Mode 

In DNS mode, the request is sent as a DNS query to the proxy.
The DPI thinks it’s a regular DNS exchange, since both the request and response appear normal.
In reality, a secure connection is established and instantly encrypted — effectively confusing DPI systems.

⸻

**📦 Features** 
	•	Full HTTPS and DNS traffic imitation
	•	Customizable fake site for deeper masking
	•	Real-time user management via NoSQL database
	•	Add new users without restarting the server
	•	Built-in Telegram bot for administration and stats
	•	Packet fragmentation and other anti-blocking techniques

⸻

## ⚙️ Quick Start

Clone and Build

git clone https://github.com/Ploxys/BurgJan-VPN
cd burgjan

# Build for Linux (example)
```
GOOS=linux GOARCH=amd64 go build -o burgjan_client ./client
```
Configuration
	•	Configure your fake site domain in the server and client code.
	•	Replace default DNS spoof target if needed (e.g., from VK to any other domain).
	•	Start the server and connect the client.

⸻
🔐 Security Notice — CRITICAL

# **⚠️ WARNING: The certificate located in the sec/ directory MUST be replaced with your own before deploying BurgJan in production.**

Using the default certificate poses a serious security risk — anyone with access to the public version can decrypt your traffic.

Generate a New Certificate

Using OpenSSL

openssl req -x509 -newkey rsa:4096 -keyout sec/key.pem -out sec/cert.pem -days 365 -nodes

Using Certbot (Let’s Encrypt)

sudo certbot certonly --standalone -d yourdomain.com

After obtaining your certificate, update paths in the server configuration.

⸻

🧾 License

MIT License

Copyright (c) 2025 Sergey Matsko

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## **Tg creater: @Remairan**


⸻

Stay safe. Always replace your certificate before using BurgJan in production.
