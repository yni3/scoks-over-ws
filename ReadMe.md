# Socks over Socket.IO

[始めにお読みください](ReadMe_Jp.md "ReadMe_Jp")

## overview

Bypass your TCP connection client to server like VPN over HTTP.
This application using Socket.IO for transport protocol. So packets behave as Pure HTTP Protocol.

YourApplication <--> client.js[TCP Proxy] <---> Proxy(optional) <---> Internet(using socket.io) <---> ReverseProxy(like nginx,optional) <---> server.js <---> Internet

## Description

Client Proxy Supports
* HTTP/HTTPS Proxy
* Sockes v4/5
* DNS(only supports a record)
* portfowarding

Connection between Client to Server is encrypted by AES.
TCP packets are Buffered and Compressed in out going connection.
Client supports chain network.If you use some machine in same Intranet, this is efficient because of Buffering.

> client.js <-> client.js <-> ... client.js <-> server.js

## requiurement

node.js >= 6.9.5
node modules in [package.json](package.json)

## usage

First, download and install dependency modules.

```
npm install
```

setting up configureation files
edit files for your envairoment

```
pushd config
cp development.json.txt development.json
cp production.json.txt production.json
popd
```

Next,export enviromental setting.And run app.

```
export NODE_ENV=production;node server.js
export NODE_ENV=production;node client.js
```

on windows(cmd.exe)

```
set NODE_ENV=production&node server.js
set NODE_ENV=production&node client.js
```

> Note. not export "NODE_ENV" variable apps uses development.json.

## setting

You can see all setting example at config/default.json. If you don't define keys at development.json or production.json, default.json setting are used.

```
"AUTH_USER": "", //username for authinication (only sigle user support)
"AUTH_PASS": "", //password for authinication (only sigle user support)
"CLIENT_USER_AGENT":"WinHttpRequest", //useragent using socket.io
"CLIENT_HOST_NAME": "localhost",  //client.js binds ports this host name
"CLIENT_OUTGOING_SOCKS": "http://hostname",
"CLIENT_SOCKS5_PORT": 1080,    //define 0 disabled
"CLIENT_SOCKS4_PORT": 1081,    //define 0 disabled
"CLIENT_HTTP_PROXY_PORT": 8000,  //define 0 disabled
"CLIENT_DNS_PORT": 53,   //define 0 disabled
"CLIENT_BRIDGE_PORT": 1800,   //chain connection port.child make connetion "CLIENT_SERVER_ADDRESS".define 0 disabled
"CLIENT_SERVER_ADDRESS": "https://exsample.com",  //define server.js address or parent client.js port.
"CLIENT_SERVER_PATH": "/",    //define URL path to server.js
"CLIENT_WEBSOCKET_ONLY" : false,  //make scoket.io using webscoekt only
"CLIENT_RECONNECTION_DELAY" : 10000,  //milli second
"CLIENT_PORT_FORWARDS" : [   //client.js binding portfowardfing
        {
            "to" : "foo.com",
            "port" : 80,
            "bind" : 18080
        },
        {
            "to" : "127.0.0.1",
            "port" : 443,
            "bind" : 18081
        }
    ],
"DATA_FLUSH_INTERVAL": 66, //Buffers flash interval (milli second)(large=good for traffic size,small=good for latency)(client.js applies server setting,in chain parent setting applies for child)
"SERVER_PATH": "/",        //define URL path in server.js
"SERVER_PORT": 443, 	   //bind port on server.js
"log4js":{} //settings for log4-js
```

## LICENCE
[BSD3](LICENSE.md "BSD3")
