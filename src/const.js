/* 
 * 固定設定のファイル
 */

function define(name, value) {
    Object.defineProperty(exports, name, {
        value: value,
        enumerable: true
    });
}

define("PROTOCOL_VERSION", 0.5);
define("BUFFER_FLASH_LENGTH", 1068);

//SIOイベント
define("SIO_CMD_WELCOME", "w");
define("SIO_CMD_AUTH", "p");
define("SIO_CMD_AUTH_ACK", "q");
define("SIO_CMD_SESSION_READY", "g");
define("SIO_CMD_ABORT", "a");
define("SIO_CMD_SHUTDOWN", "s");
define("SIO_CMD_TRANSFER", "t");
//SIO emitラップ
define("SIO_EMIT_COMMAND",0);
define("SIO_EMIT_DATA",1);
//SIO 内部 ソケット管理イベント
define("SIO_CMD_CONNECT", "c");
define("SIO_CMD_ERROR", "e");
define("SIO_CMD_CLOSE", "f");
define("SIO_CMD_DATA", "d");
define("SIO_CMD_DNS", "n");
define("SIO_CMD_HTTP_REQ", "h");
define("SIO_CMD_HTTP_RES", "r");

