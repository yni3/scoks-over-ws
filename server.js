var path = require('path');
var config = require('config');
var log4js = require('log4js');
var lib = require('auto-loader').load(__dirname + path.sep + 'src');
var util = lib.util;
var def = lib.const;
var TransBuffer = lib.TransBuffer;
var RecivBuffer = lib.RecivBuffer;
var fs = require('fs');
var http = require("http");
var socketio = require("socket.io");
var net = require("net");
var crypto = require('crypto');
var dns = require('dns');
var net_sockets = {};

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
    var length = Object.keys(net_sockets).length;
    Logger.system.debug("[CHECK] %d client connected. mem %d.", length, mem);
    var nos = "";
    var current = new Date();
    for (var client in net_sockets) {
        if (!net_sockets[client].authed)
        {
            var executionTime = current.getTime() - net_sockets[client].connected_time.getTime();
            var access_info = net_sockets[client].access_info;
            if (executionTime > 120000) { //120秒
                //認証待ちに時間かかりすぎ
                Logger.system.warn("[CHECK] client_%d (%s) waiting for auth for a long time.It will disconnect.", client, access_info);
                net_sockets[client].abort("[SYSTEM]Waiting for auth for a long time.It will disconnect.", def.SIO_CMD_SHUTDOWN);
                net_sockets[client].self.disconnect(); //disconnectハンドラにより、net_sockets[client]は除去される
            }
            continue;
        }
        var c_length = Object.keys(net_sockets[client].socks).length;
        Logger.system.debug("[CHECK] client %d allocated %d connection.", client, c_length);
        var nos = "";
        for (var no in net_sockets[client].socks) {
            nos += "" + no + ",";
        }
        Logger.system.debug("[CHECK] client_%d UP %s , DOWN %s", client, util.formatBytes(net_sockets[client].recived_data_size), util.formatBytes(net_sockets[client].send_data_size));
        Logger.system.debug("[CHECK] client_%d letf: %s", client, nos);
    }
}, 20000);//単位ms 20秒

var server = http.createServer(function (req, res) {
    res.writeHead(403, {"Content-Type": "text/html"});
    res.write("denied");
    res.end();
}).listen(config.get("SERVER_PORT"));

var io = socketio.listen(server, {
    path: config.get("SERVER_PATH")
});

Logger.system.info("server started ",config.get("SERVER_PORT"));

io.sockets.on("connection", function (socket) {
    var id = Object.id(socket);
    net_sockets[id] = {};
    net_sockets[id].self = socket;
    net_sockets[id].socks = {};
    net_sockets[id].connected_time = new Date();
    net_sockets[id].authed = false;
    net_sockets[id].client_pub_key = null;
    net_sockets[id].server_keys = null;
    var access_info = "NaN";
    if (socket.handshake.address) {
        access_info = socket.handshake.address.toString();
    }
    net_sockets[id].access_info = access_info;
    var new_server_key_pair = crypto.getDiffieHellman('modp5');
    new_server_key_pair.generateKeys();
    net_sockets[id].server_keys = new_server_key_pair;
    var abort = function (msg, command) {
        var cmd = command || def.SIO_CMD_ABORT;
        Logger.system.error("[SIO]abort client_%d:%s:%s", id, access_info, msg);
        socket.emit(cmd, msg);
        socket.disconnect();
    };
    net_sockets[id].abort = abort;
    net_sockets[id].send_data_size = 0;
    net_sockets[id].recived_data_size = 0;
    var send_buffer = TransBuffer.Create(def.BUFFER_FLASH_INTERVAL);
    send_buffer.cb_size = function (size) {
        net_sockets[id].send_data_size += size;
    };
    var reciver = RecivBuffer.Create();
    reciver.cb_size = function (size) {
        net_sockets[id].recived_data_size += size;
    };
    Logger.access.info('[SIO] %s connect as client_%d ', access_info, id);
    //-------------------------------------------------------
    //認証イベント
    //-------------------------------------------------------
    //鍵送信
    socket.emit(def.SIO_CMD_WELCOME, {
        key: net_sockets[id].server_keys.getPublicKey()
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
        var shared_key = net_sockets[id].server_keys.computeSecret(client_pubkey, null, 'base64');
        //共通鍵のハッシュを暗号パスワードにする
        var hash = crypto.createHash("sha256");
        hash.update(shared_key);
        var shared_pass = hash.digest().slice(0, 16);
        Logger.system.debug("[SIO]client_%d: SESSION PASS %s", id, shared_pass.toString('base64'));
        net_sockets[id].shared_pass = shared_pass;
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
                interval : config.get("DATA_FLUSH_INTERVAL")
            }, shared_pass));
            Logger.system.info("[SIO]client_%d: authed", id);
            net_sockets[id].authed = true;
            //emit可能
            send_buffer.start(socket, shared_pass, config.get("DATA_FLUSH_INTERVAL"));
            reciver.setPass(shared_pass);
            Logger.access.info('[SIO] client_%d(%s) : %s', id, access_info, decrypted.info);
        } else {
            Logger.system.info(decrypted);
            abort("your username or password is invalid", "shn");
            return;
        }
    });
    //クライアント送信開始
    socket.on(def.SIO_CMD_SESSION_READY, function (data, ack) {
        Logger.system.info("[SIO]client_%d: sess_ready", id);
        var recived = util.decrypt(data, net_sockets[id].shared_pass);
        if (recived.client_id !== id) {
            abort("your username or password is invalid");
        } else {
            ack(true);
        }
    });
    //-------------------------------------------------------
    //システムのイベント
    //-------------------------------------------------------
    socket.on("disconnect", function () {
        Logger.access.info('[SIO] client_%d(%s): disconnected', id, access_info);
        Logger.access.info("[SIO] client_%d(%s): UP %s , DOWN %s", id, access_info, util.formatBytes(net_sockets[id].recived_data_size), util.formatBytes(net_sockets[id].send_data_size));
        for (var index in net_sockets[id].socks) {
            net_sockets[id].socks[index].___is_closed = true; //destroy後にcloseハンドラが呼ばれても影響がでないようにする。
            net_sockets[id].socks[index].destroy();
        }
        net_sockets[id] = {};
        delete net_sockets[id];
        //emitタスクの停止
        send_buffer.stop();
        reciver.Clear();
    });
    //-------------------------------------------------------
    //プロキシトンネル関連のイベント
    //-------------------------------------------------------
    socket.on(def.SIO_CMD_TRANSFER, function (data) {
        if (!net_sockets[id].authed) {
            //認証していない場合、無効化
            abort("unauthed");
            return;
        }
        reciver.onData(data);
    });
    //接続
    reciver.cb_connect = function (recived) {
        if (recived.c_id) {
            Logger.system.debug('[TRANS]client_%d: CONN reservied %s', id, recived.c_id);
            //------------------------------------------------
            //CONNコマンドに合わせ、ブリッジするソケットを開く
            var net_socket = new net.Socket();
            net_sockets[id].socks[recived.c_id] = net_socket;
            net_socket.connect(recived.port, recived.host);
            util.addPropaty(net_socket, "___is_closed", false);
            Logger.access.info('[NET]client_%d: %s requests connect to %s:%d ', id, access_info, recived.host, recived.port);
            net_socket.on("data", function (reciv) {
                send_buffer.emit(def.SIO_CMD_DATA, {
                    c_id: recived.c_id,
                    c_data: reciv
                });
            });
            net_socket.on("error", function (reciv) {
                Logger.system.warn('[NET]client_%d: ERROR:', id, reciv);
                if (!net_socket.___is_closed) {
                    send_buffer.emit(def.SIO_CMD_ERROR, {
                        c_id: recived.c_id,
                        c_data: reciv
                    });
                }
                try {
                    net_socket.destroy();
                    delete net_sockets[id].socks[recived.c_id];
                } catch (e) {
                }
            });
            net_socket.on("close", function (reciv) {
                Logger.system.debug('[NET]client_%d: CLOSE %s', id, recived.c_id);
                Logger.system.debug('[TRANS]client_%d: send %s clz command"', id, recived.c_id);
                if (!net_socket.___is_closed) {
                    send_buffer.emit(def.SIO_CMD_CLOSE, {
                        c_id: recived.c_id,
                        c_data: reciv
                    });
                }
                try {
                    net_socket.destroy();
                    delete net_sockets[id].socks[recived.c_id];
                } catch (e) {
                }
            });
        }
    };
    // メッセージ送信（送信者にも送られる）
    reciver.cb_data = function (recived) {
        Logger.system.debug('[TRANS]client_%d: data', id);
        if (recived.c_id) {
            if (net_sockets[id].socks[recived.c_id]) {
                net_sockets[id].socks[recived.c_id].write(recived.c_data);
            } else {
                Logger.system.debug("[TRANS]server connection not found");
            }
        }
    };
    //エラー発生
    reciver.cb_error = function (recived) {
        if (recived.c_id) {
            Logger.system.debug('[TRANS]client_%d: error', id);
            if (net_sockets[id].socks[recived.c_id]) {
                net_sockets[id].socks[recived.c_id].end();
            } else {
                Logger.system.debug("[TRANS]server connection not found");
            }
        }
    };
    //ソケット切断要求
    reciver.cb_close = function (recived) {
        Logger.system.debug('[TRANS]client_%d: close', id);
        if (recived.c_id) {
            if (net_sockets[id].socks[recived.c_id]) {
                net_sockets[id].socks[recived.c_id].end();
            } else {
                Logger.system.debug("[TRANS]server connection not found");
            }
        }
    };
    //DNSクエリ
    reciver.cb_dns = function (recived) {
        if (recived.c_id) {
            Logger.system.debug('[TRANS]client_%d: dns', id, recived.c_id);
            dns.resolve(recived.name, recived.type, function (err, addresses) {
                Logger.system.debug("[DNS][err]", err);
                Logger.system.debug("[DNS][addresses]", addresses);
                if (addresses)
                {
                    send_buffer.emit(def.SIO_CMD_DNS,
                            {
                                c_id: recived.c_id,
                                name: recived.name,
                                type: recived.type,
                                c_data: addresses,
                                err: err
                            });
                } else {
                    send_buffer.emit(def.SIO_CMD_DNS,
                            {
                                c_id: recived.c_id,
                                name: recived.name,
                                type: recived.type,
                                err: err
                            });
                }
            });
        }
    };
    //HTTPトンネル関連のイベント
    reciver.cb_http_req = function (recived) {
        if (recived.c_id) {
            Logger.access.info('[TRANS][hcon]connect client_%d id_%s %s:%s%d%s', id, recived.c_id, recived.method, recived.host, recived.port, recived.path);
            var request = http.request(
                    {host: recived.host,
                        port: recived.port,
                        path: recived.path,
                        method: recived.method,
                        headers: recived.headers
                    },
                    function (response) {
                        //ヘッダ情報は、先に書く
                        Logger.system.debug('[TRANS][hcon]res:%d', response.statusCode);
                        send_buffer.emit(def.SIO_CMD_HTTP_RES,
                                {
                                    c_id: recived.c_id,
                                    status: response.statusCode,
                                    headers: response.headers
                                });
                        response.on('data', function (data) {
                            send_buffer.emit(def.SIO_CMD_DATA, {
                                c_id: recived.c_id,
                                c_data: data
                            });
                        });
                        response.on('error', function (err) {
                            Logger.system.warn('[TRANS][hcon] id_%s error', recived.c_id);
                            send_buffer.emit(def.SIO_CMD_ERROR,
                                    {
                                        c_id: recived.c_id,
                                        c_data: err
                                    });
                            delete net_sockets[id].socks[recived.c_id];
                        });
                        response.on('end', function () {
                            Logger.system.debug('[TRANS][hcon] id_%s response end', recived.c_id);
                            send_buffer.emit(def.SIO_CMD_CLOSE,
                                    {
                                        c_id: recived.c_id,
                                        c_data: null
                                    });
                            delete net_sockets[id].socks[recived.c_id];
                        });
                    }
            );
            request.on('error', function (reciv) {
                Logger.system.warn('[TRANS][hcon]on error client_%d id_%s', id, recived.c_id);
                Logger.system.warn('[TRANS][hcon]on error:', reciv);
                send_buffer.emit(def.SIO_CMD_ERROR, {
                    c_id: recived.c_id,
                    c_data: reciv
                });
                delete net_sockets[id].socks[recived.c_id];
            });
            //HTTPは、受け取り側のソケットと送信側のソケットが異なるので、
            //サーバのnet_socketsは受信、SIOコマンドを送信に使う。
            net_sockets[id].socks[recived.c_id] = request;
        }
    };
});