var config = require('config');
var log4js = require('log4js');
log4js.configure(config.log4js.configure);

function define(name, value) {
    Object.defineProperty(exports, name, {
        value: value,
        enumerable: true
    });
}

define("system",log4js.getLogger('system'));
define("access",log4js.getLogger('access'));