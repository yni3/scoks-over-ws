# Socks over Socket.IO

## overview

VPNのようにサーバクライアント間でTCP接続をブリッジするアプリケーションです。
Socket.IOを使用しているため、HTTP pollingで接続でき、ほぼすべてのプロキシを経由することができます。

YourApplication <--> client.js[TCP Proxy] <---> Proxy(optional) <---> Internet(using socket.io) <---> ReverseProxy(like nginx,optional) <---> server.js <---> Internet

## Description

クライアント側でサポートされているプロトコル
* HTTP/HTTPS Proxy
* Sockes v4/5
* DNS(only supports a record)
* portfowarding

その他
* AESによる暗号化
* すべてのパケットはバッファリングと圧縮を行うので、効率的に通信できます
* イントラネット内で、複数のクライアントを使う場合、クライアント同士を接続させることができます。インターネット側への接続を絞ることで効率的に通信することができます。

> client.js <-> client.js <-> ... client.js <-> server.js

## requiurement

node.js >= 6.9.5
node modules in [package.json](package.json)

## usage

node.jsを使用するので、最初にnpmコマンドで、依存ライブラリをインストールしてください。

```
npm install
```

設定ファイルを用意します。
(configモジュールを使用しています)

```
pushd config
cp development.json.txt development.json
cp production.json.txt production.json
popd
```

productionの環境変数を指定すれば、production.jsonの設定が。何も指定しなければ、development.jsonの設定が読み込まれます。
どちらにも定義されていない設定は、default.jsonの設定を読み込みます。
(configモジュールの通りです。)

```
export NODE_ENV=production;node server.js
export NODE_ENV=production;node client.js
```

windows(cmd.exe)

```
set NODE_ENV=production&node server.js
set NODE_ENV=production&node client.js
```

## setting

default.jsonの項目の説明
これらのなかから、変更の必要のあるキーをproduction/development.jsonで再定義(上書きされます)することで、独自の設定ができます。

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
