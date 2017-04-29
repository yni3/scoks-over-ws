/* 
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
process.on('uncaughtException', function (err) {
    Logger.system.error('uncaughtException : ', err);
});
//----------------------------------------------------------------

function define(name, value) {
    Object.defineProperty(exports, name, {
        value: value,
        enumerable: true
    });
}

var RecivBuffer = function ()
{
    this.bufferd_queue = {};
    this.pass = "";
    this.socket = null;
    //define("SIO_CMD_CONNECT", "c");
    this.cb_connect = null;
    //define("SIO_CMD_ERROR", "e");
    this.cb_error = null;
    //define("SIO_CMD_CLOSE", "f");
    this.cb_close = null;
    //define("SIO_CMD_DATA", "d");
    this.cb_data = null;
    //define("SIO_CMD_DNS", "n");
    this.cb_dns = null;
    //define("SIO_CMD_HTTP_REQ", "h");
    this.cb_http_req = null;
    //define("SIO_CMD_HTTP_RES", "r");
    this.cb_http_res = null;
    //受信したデータを取得
    this.cb_size = function(data_byte_size){};
};

RecivBuffer.prototype.setPass = function(pass){
    this.pass = pass;
};

RecivBuffer.prototype.onData = function (data)
{
    //Logger.system.debug("[RecivBuffer] onData");
    if (!this.bufferd_queue[data.e]) {
        this.bufferd_queue[data.e] = new Buffer(0);
    }
    if (data.f) {
        var reciv = Buffer.concat([this.bufferd_queue[data.e], data.d]);
        this.Final(reciv);
        delete this.bufferd_queue[data.e];
    } else {
        this.bufferd_queue[data.e] = Buffer.concat([this.bufferd_queue[data.e], data.d]);
    }
    this.cb_size(data.toString().length);
};

//最後のフレームが来たので、コールバック処理を行う
RecivBuffer.prototype.Final = function (reciv)
{
    Logger.system.info("[RecivBuffer] execute final total %d byte",reciv.length);
    var recieveds = util.decrypt(reciv, this.pass);
    var entry = null;
    while (entry = recieveds.shift()) {
        var command = entry[def.SIO_EMIT_COMMAND];
        var data = entry[def.SIO_EMIT_DATA];
        switch (command) {
            case def.SIO_CMD_CONNECT:
                this.cb_connect(data);
                break;
            case def.SIO_CMD_ERROR:
                this.cb_error(data);
                break;
            case def.SIO_CMD_CLOSE:
                this.cb_close(data);
                break;
            case def.SIO_CMD_DATA:
                this.cb_data(data);
                break;
            case def.SIO_CMD_DNS:
                this.cb_dns(data);
                break;
            case def.SIO_CMD_HTTP_REQ:
                this.cb_http_req(data);
                break;
            case def.SIO_CMD_HTTP_RES:
                this.cb_http_res(data);
                break;
            default:
                Logger.system.error("[RecivBuffer] Unknown command %s",command,data);
                break;
        }
    }
};

RecivBuffer.prototype.Clear = function ()
{
    for (var index in this.bufferd_queue) {
        delete this.bufferd_queue[index];
    }
    this.bufferd_queue = {};
};

var Create = function(){
    return new RecivBuffer();
};

define("Create", Create);