/*
 * データをバッファして、送信するクラス
 */
//----------------------------------------------------------------
//import section
var lib = require('auto-loader').load(__dirname);
var util = lib.util;
var def = lib.const;
var config = require('config');
//loggerの設定
var log4js = require('log4js');
log4js.configure(config.log4js.configure);
var Logger = {
    system: log4js.getLogger('system'),
    access: log4js.getLogger('access')
};
//----------------------------------------------------------------

function define(name, value) {
    Object.defineProperty(exports, name, {
        value: value,
        enumerable: true
    });
}

//オブジェクトにユニークなIDを振る
//http://stackoverflow.com/questions/1997661/unique-object-identifier-in-javascript
if (typeof Object.id === "undefined") {
    var id = 0;

    Object.id = function (o) {
        if (typeof o.__uniqueid === "undefined") {
            Object.defineProperty(o, "__uniqueid", {
                value: ++id,
                enumerable: false,
                // This could go either way, depending on your 
                // interpretation of what an "id" is
                writable: false
            });
        }

        return o.__uniqueid;
    };
}

var TransBuffer = function ()
{
    this.bufferd_queue = [];
    this.task_sig = 0;
    this.pass = "";
    this.socket = null;
    this.cb_size = function (data_byte_size) {};
};

TransBuffer.prototype.flash = function (self)
{
    //Logger.system.debug('[SIO] try flash');
    if (self.bufferd_queue.length > 0) {
        var send_data = util.encrypt(self.bufferd_queue, self.pass);
        Logger.system.debug('[SIO] flash toatal %d byte', send_data.length);
        for (var i = 0; i < send_data.length; i += def.BUFFER_FLASH_LENGTH) {
            var len = i + def.BUFFER_FLASH_LENGTH;
            if (send_data.length < len) {
                len = send_data.length;
            }
            var emit_data = send_data.slice(i, len);
            self.socket.emit(def.SIO_CMD_TRANSFER, {
                e: Object.id(send_data),
                f: ((i + def.BUFFER_FLASH_LENGTH) >= send_data.length),
                d: emit_data});
            //Logger.system.debug('[SIO] send emit %d byte', emit_data.length);
        }
        this.bufferd_queue = [];
        this.cb_size(send_data.length);
    }
};

TransBuffer.prototype.emit = function (cmd, data) {
    //Logger.system.debug('[TransBuffer] queued %s command"', cmd);
    this.bufferd_queue.push([cmd, data]);
};

TransBuffer.prototype.start = function (scoket, pass, interval) {
    if (this.task_sig === 0) {
        this.pass = pass;
        this.socket = scoket;
        var self = this;
        this.bufferd_queue = [];
        if (interval < 1) {
            interval = 1;
        } else if (interval > 1000) {
            interval = 1000;
        }
        this.task_sig = setInterval(function () {
            self.flash(self);
        }, interval);
        Logger.system.info("[START]", interval);
    }
};

TransBuffer.prototype.stop = function () {
    if (this.task_sig !== 0) {
        clearInterval(this.task_sig);
        this.task_sig = 0;
        this.bufferd_queue = [];
    }
};

var Create = function () {
    return new TransBuffer();
};

define("Create", Create);
