var crypto = require('crypto');
BufferSerializer = require("buffer-serializer");
var serializer = new BufferSerializer();
var zlib = require('zlib');
var config = require('config');
var os = require('os');
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

//オブジェクトにユニークなIDを振る
//http://stackoverflow.com/questions/1997661/unique-object-identifier-in-javascript
if (typeof Object.id == "undefined") {
    var id = 0;

    Object.id = function (o) {
        if (typeof o.__uniqueid == "undefined") {
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

function define(name, value) {
    Object.defineProperty(exports, name, {
        value: value,
        enumerable: true
    });
}

function addPropaty(obj, name, value) {
    Object.defineProperty(obj, name, {
        value: value,
        writable: true,
        enumerable: true
    });
}

var isset = function (data) {
    if (data === "" || data === null || data === undefined) {
        return false;
    } else {
        return true;
    }
};

function formatBytes(bytes) {
    if(bytes < 1024) return bytes + " Bytes";
    else if(bytes < 1048576) return(bytes / 1024).toFixed(3) + " KB";
    else if(bytes < 1073741824) return(bytes / 1048576).toFixed(3) + " MB";
    else return(bytes / 1073741824).toFixed(3) + " GB";
};

function decrypt(data, pass) {
    var decipher = crypto.createDecipher('aes192', pass);
    //
    var decrypted = decipher.update(data.toString('hex'), 'hex');
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    //--
    var obj = serializer.fromBuffer(decrypted);
    var extracted = Buffer.from(zlib.inflateRawSync(obj));
    obj = serializer.fromBuffer(extracted);
    //--
    return obj;
}

function encrypt(obj, pass) {
    var cipher = crypto.createCipher('aes192', pass);
    //--
    var dump = serializer.toBuffer(obj);
    var compressed = zlib.deflateRawSync(dump, {level: 9});
    dump = serializer.toBuffer(compressed);
    //--
    var cipheredText = cipher.update(dump, '', 'hex');
    cipheredText += cipher.final('hex');
    return Buffer(cipheredText, 'hex');
}

function getLocalInfo(){
    
    var ifaces = "";
    var interfaces = os.networkInterfaces();
    var platform = os.platform();
    var hostname = os.hostname();
    for (var name in interfaces) {
        interfaces[name].forEach(function(details){
            if (!details.internal){
                switch(details.family){
                    case "IPv4":
                        ifaces += name.toString() + ":" + details.address.toString() + ";";
                    break;
                    case "IPv6":
                        ifaces += name.toString() + ":" + details.address.toString() + ";";
                    break;
                }
            }
        });
    }
    return platform+";"+hostname+";"+ifaces;
}

define("encrypt", encrypt);
define("decrypt", decrypt);
define("addPropaty", addPropaty);
define("isset", isset);
define("formatBytes",formatBytes);
define("getLocalInfo",getLocalInfo);