'use strict';

var _ = require('lodash');
var fs = require('fs');
var path = require('path');
var ursa = require('ursa');

function Pemcrypt(options){
    options = options || {};

    var cwd = options.cwd || process.cwd();
    var pem = options.pem;

    if (!fs.existsSync(pem)){
        throw new Error('Missing .pem file. Forgot to `generateKey` first?', pem);
    }

    this.cwd = cwd;
    this.key = ursa.createPrivateKey(
        fs.readFileSync(pem)
    );
};

Pemcrypt.generateKey = function(pem, size){
    size = size || 8;

    var key = ursa.generatePrivateKey(1024 * size);
    var pemKey = key.toPrivatePem();

    fs.writeFileSync(pem, pemKey, 'utf8');

    return pemKey;
};

function crypto(encrypt){
    return function(storeName, persist){
        var target, source, sourceName, out;
        var pemjson = path.join(this.cwd, storeName + '.pemjson');
        var rawjson = path.join(this.cwd, storeName + '.json');

        if (encrypt) {
            target = pemjson;
            source = rawjson;
            sourceName = 'Raw .json';
        } else {
            target = rawjson;
            source = pemjson;
            sourceName = 'Encrypted .pemjson';
        }

        if (!fs.existsSync(source)){
            throw new Error(sourceName, 'store not found', source);
        }

        var data = fs.readFileSync(source);
        
        if (encrypt) {
            out = this.key.encrypt(data, 'utf8');   
        } else {
            out = this.key.decrypt(data, undefined, 'utf8');
        }

        if(persist){
            fs.writeFileSync(target, out, 'utf8');  
        }

        return out;
    };
}

Pemcrypt.prototype.encrypt = crypto(true);
Pemcrypt.prototype.decrypt = crypto(false);

module.exports = function(){
    var args = _.toArray(arguments);
    return new (Function.prototype.bind.apply(Pemcrypt, [null].concat(args)))();
};

module.exports.generateKey = Pemcrypt.generateKey.bind(Pemcrypt)