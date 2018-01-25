var path = require('path');
var config = require('config');
var log4js = require('log4js');
var lib = require('auto-loader').load(__dirname + path.sep + 'src');
var util = lib.util;
var def = lib.const;
var RecivBuffer = lib.RecivBuffer;
var TransBuffer = lib.TransBuffer;
var socks5 = require('socksv5');
var socks4 = require('socks4');
var sio_client = require('socket.io-client');
var HttpProxyAgent = require('http-proxy-agent');
var HttpsProxyAgent = require('https-proxy-agent');
var crypto = require('crypto');
var dnsd = require('dnsd');
var net = require("net");
var http = require('http');
var socketio = require("socket.io");
var reciver = RecivBuffer.Create();
var transmitter = TransBuffer.Create();
var socket_incetance_counter = 0;
var sio_socket = null;
var sio_acceptable = false;
var shared_pass = null;
var bridge_sockets = {};

var ClientSocket = function () {
    if (!(this instanceof ClientSocket)) {
        return new ClientSocket();
    }
    this.socket = null;     //書き込みソケット
    this.is_self = true;    //自分のソケットかピアのものか
    this.peer = -1; //ピアID
    this.p_id = -1; //ピアの接続ID
    //upとdownに分かれているとき、キューを閉じる判定に使う(HTTP)
    this.is_up_close = true;
    this.is_down_close = true;
    //通信速度制限
    this.emit_data_size = 0;
    this.last_mesured_time = 0;
    this.pause_locker = false;
};
ClientSocket.prototype.checkSpeed = function (data_size)
{
    var timePassed = Date.now() - this.last_mesured_time;
    if (timePassed > 1000) {
        //前回計測から1秒以上経過しているなら計測時刻を更新して終了
        this.last_mesured_time = Date.now();
        this.emit_data_size = data_size;
        return;
    } else {
        this.emit_data_size += data_size;
        //通信レート上限を超えると一時停止
        if (this.emit_data_size > config.CLIENT_OUTGOING_LIMIT) {
            var that = this;
            if (!this.pause_locker) {
                this.pause_locker = true;
                this.socket.pause();
                Logger.system.debug("Limit Rate %dms", 1000 - timePassed);
                setTimeout(function () {
                    Logger.system.debug("Wakeup Rate");
                    that.socket.resume();
                    that.pause_locker = false;
                }, 1000 - timePassed);
            }
        }
    }
};
    
var client_sockets = {};

//websocket接続時に、SSLモードだとエラーになる
//nodeとブラウザと証明書リストが異なる？
//内部認証があるので、とりあず無効
process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';

log4js.configure(config.log4js.configure);
var Logger = {
    system: log4js.getLogger('system'),
    access: log4js.getLogger('access')
};
process.on('uncaughtException', function (err) {
    Logger.system.error('uncaughtException : ', err);
});

//残存ソケット数を取得(いつまでも残っているようであれば、ゾンビの可能性)
setInterval(function () {
    var mem = process.memoryUsage().rss;
    var length = Object.keys(client_sockets).length;
    Logger.system.info("[CHECK] object is allowd %d. mem %d.", length, mem);
    var nos = "";
    for (var no in client_sockets) {
        nos += "" + no + ",";
    }
    Logger.system.info("[CHECK] letf: %s", nos);
}, 20000);//単位ms 20秒

//--------------------------------------------------------------------
// DNSサーバー
//--------------------------------------------------------------------
if (config.get("CLIENT_DNS_PORT") !== 0) {
    dnsd.createServer(handler).listen(config.get("CLIENT_DNS_PORT"), config.get("CLIENT_HOST_NAME"))
    Logger.system.info('DNS server listening on port %d', config.get("CLIENT_DNS_PORT"));
}
function handler(req, res) {
    Object.id(req);
    client_sockets[Object.id(res)] = new ClientSocket();
    client_sockets[Object.id(res)].socket = res;

    var question = {};
    question.name = res.question[0].name;
    question.type = res.question[0].type;
    question.class = res.question[0].class;

    if (sio_acceptable) {
        Logger.access.info('[dnsd]%s:%s/%s', req.connection.remoteAddress, req.connection.remotePort, req.connection.type);
        Logger.access.debug('[dnsd]%j', req);
        transmitter.emit(def.SIO_CMD_DNS,
                {
                    c_id: Object.id(res),
                    name: question.name,
                    type: question.type,
                    class: question.class
                }
        );
    } else {
        Logger.access.info('[DNS]denied %s:%s/%s', req.connection.remoteAddress, req.connection.remotePort, req.connection.type);
        res.end();
    }
}
//--------------------------------------------------------------------
// ブリッジ サーバー
//--------------------------------------------------------------------
function startBeidgeServer() {
    var server = http.createServer(function (req, res) {
        res.writeHead(403, {"Content-Type": "text/html"});
        res.write("denied\n");
        res.end();
    }).listen(config.get("CLIENT_BRIDGE_PORT"), function () {
        Logger.system.debug("Bridge start port %d", config.get("CLIENT_BRIDGE_PORT"));
    });
    var io = socketio.listen(server);
    io.sockets.on("connection", function (socket) {
        var id = Object.id(socket);
        var br_reciver = RecivBuffer.Create();
        var br_transmitter = TransBuffer.Create();
        bridge_sockets[id] = {};
        bridge_sockets[id].socket = socket;
        bridge_sockets[id].emit = function (c, d) {
            br_transmitter.emit(c, d);
        };
        bridge_sockets[id].connected_time = new Date();
        bridge_sockets[id].authed = false;
        bridge_sockets[id].client_pub_key = null;
        bridge_sockets[id].server_keys = null;
        bridge_sockets[id].shared_pass = "";
        var access_info = "NaN";
        if (socket.handshake.address) {
            access_info = socket.handshake.address.toString();
        }
        bridge_sockets[id].access_info = access_info;
        var new_server_key_pair = crypto.getDiffieHellman('modp5');
        new_server_key_pair.generateKeys();
        bridge_sockets[id].server_keys = new_server_key_pair;
        var abort = function (msg, command) {
            var cmd = command || def.SIO_CMD_ABORT;
            Logger.system.error("[SIO]abort client_%d:%s:%s", id, access_info, msg);
            socket.emit(cmd, msg);
            socket.disconnect();
        };
        var bypass_close = function (csid) {
            Logger.system.warn("[SIO]soft close client_%d(%s) connection %s", id, access_info, csid);
            br_transmitter.emit(def.SIO_CMD_CLOSE,
                    {
                        c_id: csid,
                        c_data: "parent connection is lost"
                    }
            );
        };
        bridge_sockets[id].abort = abort;
        bridge_sockets[id].bypass_close = bypass_close;
        Logger.access.info('[SIO] %s connect as client_%d ', access_info, id);
        //-------------------------------------------------------
        //ブリッジ　認証イベント
        //-------------------------------------------------------
        //鍵送信
        socket.emit(def.SIO_CMD_WELCOME, {
            key: new_server_key_pair.getPublicKey()
        });
        //認証関連のコマンド
        socket.on(def.SIO_CMD_AUTH, function (data) {
            //クライアント公開鍵
            var client_pubkey = null;
            if (data.key) {
                client_pubkey = data.key;
            } else {
                abort("your username or password is invalid");
                return;
            }
            //共通鍵算出
            var shared_key = new_server_key_pair.computeSecret(client_pubkey, null, 'base64');
            //共通鍵のハッシュを暗号パスワードにする
            var hash = crypto.createHash("sha256");
            hash.update(shared_key);
            var shared_pass = hash.digest().slice(0, 16);
            Logger.system.debug("[SIO]client_%d: SESSION PASS %s", id, shared_pass.toString('base64'));
            bridge_sockets[id].shared_pass = shared_pass;
            //複号
            var decrypted = util.decrypt(data.c_data, shared_pass);
            //バージョン確認
            if (decrypted.version === def.PROTOCOL_VERSION) {
                Logger.system.info("[SIO]client_%d: protocl version is matched", id);
            } else {
                Logger.system.info("[SIO]client_%d: protocl version is not matched", id);
                Logger.system.info(decrypted);
                abort("protcol version is not matched", "shn");
                return;
            }
            //ユーザー認証
            if (decrypted.user === config.get("AUTH_USER") &&
                    decrypted.pass === config.get("AUTH_PASS")) {
                socket.emit(def.SIO_CMD_AUTH_ACK, util.encrypt({
                    client_id: id,
                    interval: config.get("DATA_FLUSH_INTERVAL")
                }, shared_pass));
                Logger.system.info("[SIO]client_%d: authed", id);
                bridge_sockets[id].authed = true;
                br_transmitter.start(socket, shared_pass, config.get("DATA_FLUSH_INTERVAL"));
                br_reciver.setPass(shared_pass);
            } else {
                Logger.system.info(decrypted);
                abort("your username or password is invalid", "shn");
                return;
            }
        });
        //クライアント送信開始
        socket.on(def.SIO_CMD_SESSION_READY, function (data, ack) {
            Logger.system.info("[SIO]client_%d: sess_ready", id);
            var recived = util.decrypt(data, bridge_sockets[id].shared_pass);
            if (recived.client_id !== id) {
                abort("your username or password is invalid");
            } else {
                ack(true);
            }
        });
        //-------------------------------------------------------
        //ブリッジ　システムのイベント
        //-------------------------------------------------------
        socket.on("disconnect", function () {
            Logger.access.info('[SIO]client_%d: disconnected', id);
            //保留
            for (var index in client_sockets) {
                if (client_sockets[index].peer === id) {
                    delete client_sockets[index];
                }
            }
            delete bridge_sockets[id];
            br_transmitter.stop();
        });
        //-------------------------------------------------------
        //ブリッジ　プロキシトンネル関連のイベント(転送)
        //-------------------------------------------------------
        socket.on(def.SIO_CMD_TRANSFER, function (data) {
            if (!bridge_sockets[id].authed) {
                abort("unauthed"); //未認証
                return;
            }
            br_reciver.onData(data);
        });
        //接続
        br_reciver.cb_connect = function (recived) {
            if (recived.c_id) {
                Logger.system.debug('[BRIDGE]peer_%d: CONN reservied %d', id, recived.c_id);
                if (sio_acceptable) {
                    var csid = id + "_" + recived.c_id;
                    client_sockets[csid] = new ClientSocket();
                    client_sockets[csid].socket = socket;
                    client_sockets[csid].is_self = false;
                    client_sockets[csid].peer = id;
                    client_sockets[csid].p_id = recived.c_id;
                    transmitter.emit(def.SIO_CMD_CONNECT,
                            {
                                c_id: csid,
                                host: recived.host,
                                port: recived.port
                            }
                    );
                } else {
                    bypass_close(recived.c_id);
                }
            }
        };
        // メッセージ送信（送信者にも送られる）
        br_reciver.cb_data = function (recived) {
            if (recived.c_id) {
                Logger.system.debug('[BRIDGE]peer_%d: data', id);
                if (sio_acceptable) {
                    var csid = id + "_" + recived.c_id;
                    transmitter.emit(def.SIO_CMD_DATA,
                            {
                                c_id: csid,
                                c_data: recived.c_data
                            }
                    );
                } else {
                    bypass_close(recived.c_id);
                }
            }
        };
        //エラー発生
        br_reciver.cb_error = function (recived) {
            if (recived.c_id) {
                Logger.system.debug('[BRIDGE]peer_%d: conn_%d: error', id, recived.c_id);
                if (sio_acceptable) {
                    var csid = id + "_" + recived.c_id;
                    transmitter.emit(def.SIO_CMD_ERROR,
                            {
                                c_id: csid,
                                c_data: recived.c_data || null
                            }
                    );
                    if (client_sockets[csid]) {
                        if (!client_sockets[csid].is_up_close) {
                            Logger.system.debug('[BRIDGE]peer_%d: conn_%d: UP CLOSE', id, recived.c_id);
                            client_sockets[csid].is_up_close = true;
                        }
                        if (client_sockets[csid].is_up_close && client_sockets[csid].is_down_close) {
                            delete client_sockets[csid];
                        }
                    }
                } else {
                    bypass_close(recived.c_id);
                }
            }
        };
        //ソケット切断要求
        br_reciver.cb_close = function (recived) {
            if (recived.c_id) {
                if (sio_acceptable) {
                    var csid = id + "_" + recived.c_id;
                    Logger.system.debug('[BRIDGE]peer_%d: conn_%d: close', id, recived.c_id);
                    transmitter.emit(def.SIO_CMD_CLOSE,
                            {
                                c_id: csid,
                                c_data: recived.c_data || null
                            }
                    );
                    if (client_sockets[csid]) {
                        if (!client_sockets[csid].is_up_close) {
                            Logger.system.debug('[BRIDGE]peer_%d: conn_%d: UP CLOSE', id, recived.c_id);
                            client_sockets[csid].is_up_close = true;
                        }
                        if (client_sockets[csid].is_up_close && client_sockets[csid].is_down_close) {
                            delete client_sockets[csid];
                        }
                    }
                } else {
                    bypass_close(recived.c_id);
                }
            }
        };
        //DNSクエリ
        br_reciver.cb_dns = function (recived) {
            if (recived.c_id) {
                Logger.system.debug('[BRIDGE]peer_%d: conn_%d: dns', id, recived.c_id);
                if (sio_acceptable) {
                    var csid = id + "_" + recived.c_id;
                    client_sockets[csid] = new ClientSocket();
                    client_sockets[csid].socket = socket;
                    client_sockets[csid].is_self = false;
                    client_sockets[csid].peer = id;
                    client_sockets[csid].p_id = recived.c_id;
                    transmitter.emit(def.SIO_CMD_DNS,
                            {
                                c_id: csid,
                                name: recived.name,
                                type: recived.type,
                                class: recived.class
                            }
                    );
                } else {
                    bypass_close(recived.c_id);
                }
            }
        };
        //HTTPクエリ
        br_reciver.cb_http_req = function (recived) {
            if (recived.c_id) {
                Logger.access.info('[BRIDGE]peer_%d conn_%d: http %s:%s%d%s', id, recived.c_id, recived.method, recived.host, recived.port, recived.path);
                if (sio_acceptable) {
                    var csid = id + "_" + recived.c_id;
                    client_sockets[csid] = new ClientSocket();
                    client_sockets[csid].socket = socket;
                    client_sockets[csid].is_self = false;
                    client_sockets[csid].peer = id;
                    client_sockets[csid].p_id = recived.c_id;
                    client_sockets[csid].is_up_close = false;
                    client_sockets[csid].is_down_close = false;
                    transmitter.emit(def.SIO_CMD_HTTP_REQ,
                            {
                                c_id: csid,
                                host: recived.host,
                                port: recived.port,
                                path: recived.path,
                                method: recived.method,
                                headers: recived.headers
                            }
                    );
                } else {
                    bypass_close(recived.c_id);
                }
            }
        };
    });
}

if (config.get("CLIENT_BRIDGE_PORT") !== 0)
{
    startBeidgeServer();
}

//--------------------------------------------------------------------
// TCPフォワードサーバー
//--------------------------------------------------------------------
var start_forward_server = function (index) {
    var to = config.CLIENT_PORT_FORWARDS[index].to;
    var port = config.CLIENT_PORT_FORWARDS[index].port;
    var bind = config.CLIENT_PORT_FORWARDS[index].bind;
    net.createServer(function (socket) {
        client_sockets[Object.id(socket)] = new ClientSocket();
        client_sockets[Object.id(socket)].socket = socket;
        if (sio_acceptable) {
            transmitter.emit(def.SIO_CMD_CONNECT,
                    {
                        c_id: Object.id(socket),
                        host: to,
                        port: port
                    }
            );
        }
        //アプリケーションイベント
        socket.on('data', function (data) {
            Logger.system.debug('[FOWARD] data %d kb', data.toString().length);
            if (sio_acceptable) {
                transmitter.emit(def.SIO_CMD_DATA,
                        {
                            c_id: Object.id(socket),
                            c_data: data
                        }
                );
            }
        });
        // 'close'イベントハンドラー
        socket.on('close', function (had_error) {
            Logger.system.debug('[FOWARD] CLOSED.' + ((had_error) ? " with ERROR" : ""));
            try {
                if (sio_acceptable) {
                    transmitter.emit(def.SIO_CMD_CLOSE,
                            {
                                c_id: Object.id(socket)
                            }
                    );
                }
                socket.end();
                delete client_sockets[Object.id(socket)];
            } catch (e) {
            }
        });
        // 'errer'イベントハンドラー
        socket.on('error', function (err) {
            Logger.system.warn('[FOWARD]ERROR: ' + err.stack);
            try {
                if (sio_acceptable) {
                    transmitter.emit(def.SIO_CMD_ERROR,
                            {
                                c_id: Object.id(socket)
                            }
                    );
                }
                socket.end();
                delete client_sockets[Object.id(socket)];
            } catch (e) {
            }
        });
    }).listen(bind, function () {
        Logger.system.info("[FORWARD] %s:%d is bind on %d", to, port, bind);
    });
};

for (var index in config.CLIENT_PORT_FORWARDS)
{
    start_forward_server(index);
}
//--------------------------------------------------------------------
// HTTPプロキシ サーバー
//--------------------------------------------------------------------
function startHttpServer() {
    var url = require('url');
    var server = http.createServer(function (request, response) {
        var acess_info = url.parse(request.url);
        //接続命令
        if (sio_acceptable) {
            //受信用ソケット
            client_sockets[Object.id(response)] = new ClientSocket();
            client_sockets[Object.id(response)].socket = response;

            Logger.access.info("[HTTP][request] %s:%d", acess_info.hostname, (acess_info.port || 80));
            transmitter.emit(def.SIO_CMD_HTTP_REQ,
                    {
                        c_id: Object.id(response),
                        host: acess_info.hostname,
                        port: acess_info.port || 80,
                        path: acess_info.path,
                        method: request.method,
                        secure: false,
                        headers: request.headers
                    }
            );
        } else {
            response.writeHead(403, {"Content-Type": "text/html"});
            response.write("denied");
            response.end();
            return;
        }
        //送信
        request.on('data', function (data) {
            Logger.system.debug('[HTTP][request] data %d kb', data.toString().length);
            if (sio_acceptable) {
                transmitter.emit(def.SIO_CMD_DATA,
                        {
                            c_id: Object.id(response),
                            c_data: data
                        }
                );
            }
        });
        //リクエスト終了
        request.on('end', function () {
            //サーバ側のリクエストに、endを書き込む。
            Logger.system.debug('[HTTP][request] end. Close request');
            if (sio_acceptable) {
                transmitter.emit(def.SIO_CMD_CLOSE,
                        {
                            c_id: Object.id(response),
                            c_data: null
                        }
                );
            }
        });
        //エラー
        request.on('error', function (err) {
            Logger.system.warn('[HTTP][request]ERROR: ', err);
            if (sio_acceptable) {
                transmitter.emit(def.SIO_CMD_ERROR,
                        {
                            c_id: Object.id(response)
                        }
                );
            }
            response.end();
            delete client_sockets[Object.id(response)];
        });
        //受信完了
        response.on('finish', function () {
            Logger.system.debug('[HTTP][request] response finish id_%d', Object.id(response));
            response.end();
            delete client_sockets[Object.id(response)];
        });
    });
    //request <http.IncomingMessage> Arguments for the HTTP request, as it is in the 'request' event
    //socket <net.Socket> Network socket between the server and client
    //head <Buffer> The first packet of the tunneling stream (may be empty)
    server.on('connect', function (request, socket, head) {
        var acess_info = url.parse('https://' + request.url);
        //接続命令
        if (sio_acceptable) {
            //受信用ソケット
            client_sockets[Object.id(socket)] = new ClientSocket();
            client_sockets[Object.id(socket)].socket = socket;

            socket.write('HTTP/1.0 200 Connection established\r\n\r\n');
            Logger.access.info("[HTTP][connect] %s:%d", acess_info.hostname, acess_info.port);
            transmitter.emit(def.SIO_CMD_CONNECT,
                    {
                        c_id: Object.id(socket),
                        host: acess_info.hostname,
                        port: acess_info.port || 443
                    }
            );
        } else {
            socket.write('HTTP/1.0 403 Forbidden\r\n\r\n');
            socket.write("denied");
            socket.end();
            return;
        }
        socket.on('data', function (data) {
            Logger.system.debug('[HTTP][connect] data %d kb', data.toString().length);
            if (sio_acceptable) {
                client_sockets[Object.id(socket)].checkSpeed(data.length);
                transmitter.emit(def.SIO_CMD_DATA,
                        {
                            c_id: Object.id(socket),
                            c_data: data
                        }
                );
            }
        });
        // 'close'イベントハンドラー
        socket.on('close', function (had_error) {
            Logger.system.debug('[HTTP][connect] CLOSED.' + ((had_error) ? " with ERROR" : ""));
            try {
                if (sio_acceptable) {
                    transmitter.emit(def.SIO_CMD_CLOSE,
                            {
                                c_id: Object.id(socket)
                            }
                    );
                }
                socket.end();
                delete client_sockets[Object.id(socket)];
            } catch (e) {
            }
        });
        // 'errer'イベントハンドラー
        socket.on('error', function (err) {
            Logger.system.warn('[HTTP][connect]ERROR: ' + err.stack);
            try {
                if (sio_acceptable) {
                    transmitter.emit(def.SIO_CMD_ERROR,
                            {
                                c_id: Object.id(socket)
                            }
                    );
                }
                socket.end();
                delete client_sockets[Object.id(socket)];
            } catch (e) {
            }
        });
    });
    server.listen(config.get("CLIENT_HTTP_PROXY_PORT"), function () {
        Logger.system.debug("HTTP Proxy start port %d", config.get("CLIENT_HTTP_PROXY_PORT"));
    });
}

if (config.get("CLIENT_HTTP_PROXY_PORT") !== 0)
{
    startHttpServer();
}
//--------------------------------------------------------------------
// socks サーバー
//--------------------------------------------------------------------
var send_sock_deny_message = function (socket) {
    var body = "Preparing beidge connection.";
    socket.end([
        'HTTP/1.1 403 Forbidden',
        'Connection: close',
        'Content-Type: text/plain',
        'Content-Length: ' + Buffer.byteLength(body),
        '',
        body
    ].join('\r\n'));
};
var start_scokserver = function () {
    if (config.get("CLIENT_SOCKS5_PORT") !== 0) {
        var srv = socks5.createServer(function (info, accept, deny) {
            var socket = accept(true);
            if (socket) {
                if (!sio_acceptable) {
                    Logger.access.info('[SOCK5][denied] to : ', info.dstAddr, ":", info.dstPort, " id:", Object.id(socket));
                    if (info.dstPort === 80) {
                        send_sock_deny_message(socket);
                    } else {
                        deny();
                    }
                    return;
                }
                Logger.access.info('[SOCK5] to : ', info.dstAddr, ":", info.dstPort, " id:", Object.id(socket));
                client_sockets[Object.id(socket)] = new ClientSocket();
                client_sockets[Object.id(socket)].socket = socket;
                
                if (sio_acceptable) {
                    transmitter.emit(def.SIO_CMD_CONNECT,
                            {
                                c_id: Object.id(socket),
                                host: info.dstAddr,
                                port: info.dstPort
                            }
                    );
                }
                //アプリケーションイベント
                socket.on('data', function (data) {
                    Logger.system.debug('[SCOK5] data %d byte', data.toString().length);
                    if (sio_acceptable) {
                        client_sockets[Object.id(socket)].checkSpeed(data.length);
                        transmitter.emit(def.SIO_CMD_DATA,
                                {
                                    c_id: Object.id(socket),
                                    c_data: data
                                }
                        );
                    }
                });
                // 'close'イベントハンドラー
                socket.on('close', function (had_error) {
                    Logger.system.debug('[SOCK5] CLOSED.' + ((had_error) ? " with ERROR" : ""));
                    try {
                        if (sio_acceptable) {
                            transmitter.emit(def.SIO_CMD_CLOSE,
                                    {
                                        c_id: Object.id(socket)
                                    }
                            );
                        }
                        socket.end();
                        delete client_sockets[Object.id(socket)];
                    } catch (e) {
                    }
                });
                // 'errer'イベントハンドラー
                socket.on('error', function (err) {
                    Logger.system.warn('[SOCK5]ERROR: ' + err.stack);
                    try {
                        if (sio_acceptable) {
                            transmitter.emit(def.SIO_CMD_ERROR,
                                    {
                                        c_id: Object.id(socket)
                                    }
                            );
                        }
                        socket.end();
                        delete client_sockets[Object.id(socket)];
                    } catch (e) {
                    }
                });
                accept();
            } else {
                Logger.access.info('[SOCK5][denied] to : ', info.dstAddr, ":", info.dstPort, " id:", Object.id(socket));
                deny();
            }
        });
        srv.listen(config.get("CLIENT_SOCKS5_PORT"), config.get("CLIENT_HOST_NAME"), function () {
            Logger.system.info('SOCKS5 server listening on port %d', config.get("CLIENT_SOCKS5_PORT"));
        });
        srv.useAuth(socks5.auth.None());
    }
    if (config.get("CLIENT_SOCKS4_PORT") !== 0) {
        var srv4 = socks4.createServer();
        srv4.on('connect', function (req) {
            var socket = req.socket;
            if (socket) {
                if (!sio_acceptable) {
                    Logger.access.info('[SOCK4][rejected] to :', req.host, ":", req.port, ' id:', Object.id(socket));
                    if (req.port === 80) {
                        send_sock_deny_message(socket);
                    } else {
                        req.reject();
                    }
                    return;
                }
                client_sockets[Object.id(socket)] = new ClientSocket();
                client_sockets[Object.id(socket)].socket = socket;

                Logger.access.info('[SOCK4] to :', req.host, ":", req.port, ' id:', Object.id(socket));
                transmitter.emit(def.SIO_CMD_CONNECT,
                        {
                            c_id: Object.id(socket),
                            host: req.host,
                            port: req.port
                        }
                );
                socket.on('data', function (data) {
                    Logger.system.debug('[SCOK4] data %d bytes', data.toString().length);
                    if (sio_socket) {
                        client_sockets[Object.id(socket)].checkSpeed(data.length);
                        transmitter.emit(def.SIO_CMD_DATA,
                                {
                                    c_id: Object.id(socket),
                                    c_data: data
                                }
                        );
                    }
                });
                // 'close'イベントハンドラー
                socket.on('close', function (had_error) {
                    Logger.system.debug('[SOCK4]CLOSED.' + ((had_error) ? " with ERROR" : ""));
                    try {
                        if (sio_socket) {
                            transmitter.emit(def.SIO_CMD_CLOSE,
                                    {
                                        c_id: Object.id(socket)
                                    });
                        }
                        socket.end();
                        delete client_sockets[Object.id(socket)];
                    } catch (e) {
                    }
                });
                // 'errer'イベントハンドラー
                socket.on('error', function (err) {
                    Logger.system.warn('[SOCK4]ERROR: ' + err.stack);
                    try {
                        if (sio_socket) {
                            transmitter.emit(def.SIO_CMD_ERROR,
                                    {
                                        c_id: Object.id(socket)
                                    });
                        }
                        socket.end();
                        delete client_sockets[Object.id(socket)];
                    } catch (e) {
                    }
                });
                req.accept();
            } else {
                Logger.access.info('[SOCK4][rejected] to :', req.host, ":", req.port, ' id:', Object.id(socket));
                req.reject();
            }
        });
        srv4.listen(config.get("CLIENT_SOCKS4_PORT"), config.get("CLIENT_HOST_NAME"), function () {
            Logger.system.info('SOCKS4 server listening on port %d', config.get("CLIENT_SOCKS4_PORT"));
        });
    }
};

//SOKCSプロキシ開始
start_scokserver();

//--------------------------------------------------------------------
/**
 * socket.io-client connection
 * マニュアル↓
 * https://github.com/socketio/socket.io-client/blob/master/docs/API.md
 */
//--------------------------------------------------------------------
var socketOptions = {
    //リトライ回数
    //reconnectionAttempts : Infinity,
    //リトライ間隔のペナルティ
    reconnectionDelay: config.get("CLIENT_RECONNECTION_DELAY"), //10秒間隔+-乱数で再接続間隔が伸びる
    //最大リトライ間隔
    reconnectionDelayMax: 864000000, //1日
    reconnection: true,
    timeout: 10000, //10秒
    path: config.get("CLIENT_SERVER_PATH"),
    extraHeaders: {
        "User-Agent": config.get("CLIENT_USER_AGENT")
    }
};
var proxy = process.env.HTTP_PROXY || config.get("CLIENT_OUTGOING_SOCKS");
// Using Proxy
if (proxy) {
    Logger.system.debug("[SIO]set proxy %s", proxy);
    var agent = new HttpsProxyAgent(proxy);
    //var agent = new HttpProxyAgent(proxy);
    socketOptions.agent = agent;
}
if (config.get("CLIENT_WEBSOCKET_ONLY")) {
    socketOptions.transports = ["websocket"];
}
sio_socket = sio_client.connect(config.get("CLIENT_SERVER_ADDRESS"), socketOptions);
sio_socket.on('connect', function () {
    Logger.access.info('[SIO]connected %s%s', config.get("CLIENT_SERVER_ADDRESS"), config.get("SERVER_PATH"));
    //接続開始時に、認証情報を未初期化扱いにする
    sio_acceptable = false;
});
//-------------------------------------------------------
//認証イベント
//-------------------------------------------------------
sio_socket.on(def.SIO_CMD_WELCOME, function (data) {
    Logger.system.debug("[SIO] welcome data", data);
    var server_pubkey = data.key;
    //鍵生成
    var client_keys = crypto.getDiffieHellman('modp5');
    client_keys.generateKeys();
    var shared_key = client_keys.computeSecret(server_pubkey, null, 'base64');
    //共通鍵のハッシュを暗号パスワードにする
    hash = crypto.createHash("sha256");
    hash.update(shared_key);
    shared_pass = hash.digest().slice(0, 16);
    Logger.system.debug("[SIO]SESSION PASS %s", shared_pass.toString('base64'));
    //暗号化して送信
    sio_socket.emit(def.SIO_CMD_AUTH,
            {
                key: client_keys.getPublicKey(),
                c_data: util.encrypt(
                        {
                            version: def.PROTOCOL_VERSION,
                            user: config.get("AUTH_USER"),
                            pass: config.get("AUTH_PASS"),
                            info: util.getLocalInfo()
                        }, shared_pass)
            }
    );
});
//認証成功
sio_socket.on(def.SIO_CMD_AUTH_ACK, function (data) {
    var recived = util.decrypt(data, shared_pass);
    Logger.system.info('[SIO]authed : ', recived);
    //サーバは、authedコマンドのACKで認証受理するが、
    //クライアントはサーバACK受信前に送ってしまう場合があるので、
    //クライントの認証受理をサーバのACKをベースに行う
    sio_socket.emit(def.SIO_CMD_SESSION_READY,
            util.encrypt(
                    {
                        client_id: recived.client_id
                    }, shared_pass)
            , function (response) {
                Logger.access.info('[SIO]on authed ack : ', response);
                transmitter.start(sio_socket, shared_pass, recived.interval);
                sio_acceptable = true;
            }
    );
    reciver.setPass(shared_pass);
});
//強制終了コマンド
sio_socket.on(def.SIO_CMD_SHUTDOWN, function (data) {
    Logger.system.error('[SIO]shutdown : ', data);
    for (var index in bridge_sockets) {
        bridge_sockets[index].socket.emit(def.SIO_CMD_SHUTDOWN, data);
        bridge_sockets[index].socket.disconnect();
    }
    process.exit(1);
});
//警告コマンド
sio_socket.on(def.SIO_CMD_ABORT, function (data) {
    Logger.system.error('[SIO]abort : ', data);
    //手動で切断した場合、reconnectがかからないので、手動リトライを行う
    setTimeout(function () {
        sio_socket.connect();
    }, 10000);
});
//-------------------------------------------------------
//システムイベント
//-------------------------------------------------------
sio_socket.on('connect_error', function (rs) {
    Logger.system.error('[SIO]connect_error. %s%s', config.get("CLIENT_SERVER_ADDRESS"), config.get("SERVER_PATH"), rs);
});
sio_socket.on('disconnect', function (had_error) {
    Logger.system.info('[SIO]disconnect.' + ((had_error) ? " with ERROR" : ""));
    //切断時は非認証にする
    sio_acceptable = false;
    //既存の接続を切る
    for (var index in client_sockets) {
        if (client_sockets[index].is_self) {
            client_sockets[index].socket.destroy();
        } else {
            bridge_sockets[client_sockets[index].peer].bypass_close(client_sockets[index].p_id);
        }
        delete client_sockets[index];
    }
    reciver.Clear();
    transmitter.stop();
});
sio_socket.on('error', function (had_error) {
    Logger.system.error('[SIO]error. : ' + had_error);
});
sio_socket.on('reconnect_attempt', function () {
    Logger.system.info('[SIO]trying reconnect.');
});
sio_socket.on('reconnect_failed', function (had_error) {
    Logger.system.error('[SIO]reconnect_failed. prosses end', had_error);
});
//-------------------------------------------------------
//アプリケーションイベント
//-------------------------------------------------------
sio_socket.on(def.SIO_CMD_TRANSFER, function (data) {
    reciver.onData(data);
});
reciver.cb_data = function (recived) {
    Logger.system.debug('[TRANS] data %s', recived.c_id);
    if (recived.c_id && client_sockets[recived.c_id]) {
        if (client_sockets[recived.c_id].is_self) {
            Logger.system.debug('[SOCK] write');
            client_sockets[recived.c_id].socket.write(recived.c_data);
        } else {
            bridge_sockets[client_sockets[recived.c_id].peer].emit(def.SIO_CMD_DATA,
                    {
                        c_id: client_sockets[recived.c_id].p_id,
                        c_data: recived.c_data
                    });
        }
    } else {
        Logger.system.warn('[TRANS] data %s reciver not found', recived.c_id);
    }
};
//ERROR
reciver.cb_error = function (recived) {
    Logger.system.debug('[TRANS] err ' + recived.c_id);
    if (recived.c_id && client_sockets[recived.c_id]) {
        if (client_sockets[recived.c_id].is_self) {
            client_sockets[recived.c_id].socket.end();
        } else {
            bridge_sockets[client_sockets[recived.c_id].peer].emit(def.SIO_CMD_ERROR,
                    {
                        c_id: client_sockets[recived.c_id].p_id,
                        c_data: recived.c_data
                    });
            if (!client_sockets[recived.c_id].is_down_close) {
                Logger.system.debug('[TRANS] Error %s : Down close', recived.c_id);
                client_sockets[recived.c_id].is_down_close = true;
                if (client_sockets[recived.c_id].is_up_close && client_sockets[recived.c_id].is_down_close) {
                    delete client_sockets[recived.c_id];
                }
            }
        }
    }
};
//CLOSE
reciver.cb_close = function (recived) {
    Logger.system.debug('[TRANS] Close %s', recived.c_id);
    if (recived.c_id && client_sockets[recived.c_id]) {
        if (client_sockets[recived.c_id].is_self) {
            client_sockets[recived.c_id].socket.end();
        } else {
            bridge_sockets[client_sockets[recived.c_id].peer].emit(def.SIO_CMD_CLOSE,
                    {
                        c_id: client_sockets[recived.c_id].p_id,
                        c_data: recived.c_data
                    });
            if (!client_sockets[recived.c_id].is_down_close) {
                Logger.system.debug('[TRANS] Close %s : Down close', recived.c_id);
                client_sockets[recived.c_id].is_down_close = true;
                if (client_sockets[recived.c_id].is_up_close && client_sockets[recived.c_id].is_down_close) {
                    delete client_sockets[recived.c_id];
                }
            }
        }
    }
};
//HTTP
reciver.cb_http_res = function (recived) {
    Logger.system.debug('[TRANS][HTTP RESPONSE] request_id:%s', recived.c_id);
    if (recived.c_id && client_sockets[recived.c_id]) {
        if (client_sockets[recived.c_id].is_self) {
            client_sockets[recived.c_id].socket.writeHead(recived.status, recived.headers);
        } else {
            bridge_sockets[client_sockets[recived.c_id].peer].emit(def.SIO_CMD_HTTP_RES,
                    {
                        c_id: client_sockets[recived.c_id].p_id,
                        status: recived.status,
                        headers: recived.headers
                    });
        }
    }
};
//DNS
reciver.cb_dns = function (recived) {
    Logger.system.debug('[TRANS] DNS returned', recived.c_id);
    Logger.system.debug('[TRANS] DNS returned', recived);
    if (recived.c_id && client_sockets[recived.c_id]) {
        if (client_sockets[recived.c_id].is_self) {
            var res = client_sockets[recived.c_id].socket;
            try {

                if (recived.err) {

                } else if (recived.c_data instanceof Array)
                {
                    recived.c_data.forEach(function (entry) {
                        Logger.system.info(entry);
                        switch (recived.type) {
                            case "A":
                            case "AAAA":
                                res.answer.push({name: recived.name, type: recived.type, data: entry, 'ttl': 300});
                                break;
                            case 'MX':
                                res.answer.push({name: recived.name, type: recived.type, data: [entry.priority, entry.exchange]})
                                break;
                            case "CNAME":
                        }
                    }
                    );
                } else {
                    switch (recived.type) {
                        default:
                            //res.answer.push(recived.c_data);
                    }
                }
                res.end();
            } catch (e) {
                Logger.system.error('[dnsd] error', e);
            }
        } else {
            bridge_sockets[client_sockets[recived.c_id].peer].emit(def.SIO_CMD_DNS,
                    {
                        c_id: client_sockets[recived.c_id].p_id,
                        name: recived.name,
                        type: recived.type,
                        c_data: recived.c_data,
                        err: recived.err
                    });
        }
        delete client_sockets[recived.c_id];
    }
};