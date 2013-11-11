'use strict';

var _ = require('lodash');
var fs = require('fs');
var path = require('path');
var ursa = require('ursa');
var crypto = require('crypto');
var mkdirp = require('mkdirp');

function Pemcrypt(options){
    options = options || {};

    var cwd = options.cwd || process.cwd();
    var pem = options.pem;

    if (!fs.existsSync(pem)){
        throw new Error('Missing .pem file. Forgot to use `Pemcrypt.generateKey(filename, size)` first? ' + pem);
    }

    this.cwd = cwd;
    this.key = ursa.createPrivateKey(
        fs.readFileSync(pem)
    );
    this.raw = options.raw || '.json';
    this.secure = options.secure || '.pemjson';
    this.algorithm = options.algorithm || 'aes256';
};

Pemcrypt.generateKey = function(pem, size){
    size = size || 8;

    var dir = path.dirname(pem);
    var key = ursa.generatePrivateKey(1024 * size);
    var pemKey = key.toPrivatePem();

    mkdirp.sync(dir);
    fs.writeFileSync(pem, pemKey, 'utf8');

    return pemKey;
};

function crypto(encrypt){
    return function(sourceStore, targetStore){
        var formats = {
            true: this.raw,
            false: this.secure
        };

        var sourceFile = path.join(this.cwd, sourceStore + formats[encrypt]);

        if (!fs.existsSync(sourceFile)){
            throw new Error(sourceStore + ' store not found: ' + sourceFile);
        }

        var data = fs.readFileSync(sourceFile);
        var out;

        if (encrypt) {
            out = encryption.call(this, data);
        } else {
            out = decryption.call(this, data);
        }

        if (targetStore) {

            // if targetStore is true, just use the same path
            if (targetStore === true) {
                targetStore = sourceStore;
            }

            var targetFile = path.join(this.cwd, targetStore + formats[!encrypt]);
            var targetDirectory = path.dirname(targetFile);

            mkdirp.sync(targetDirectory);
            fs.writeFileSync(targetFile, out, 'utf8');
        }

        return out;
    };
}

function encryption (data) {
    var key = this.key;

    if (this.algorithm === 'rsa') {
        return key.encrypt(data, 'utf8');
    }

    var pemKey = key.toPrivatePem();
    var cipher = crypto.createCipher(this.algorithm, pemKey);
    var encrypted = cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
    return encrypted;
}

function decryption (data) {
    var key = this.key;

    if (this.algorithm === 'rsa') {
        return key.decrypt(data, undefined, 'utf8');
    }
    var pemKey = key.toPrivatePem();
    var decipher = crypto.createDecipher(this.algorithm, pemKey);
    var decrypted = decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8');
    return decrypted;
}

Pemcrypt.prototype.encrypt = crypto(true);
Pemcrypt.prototype.decrypt = crypto(false);

module.exports = function(){
    var args = _.toArray(arguments);
    return new (Function.prototype.bind.apply(Pemcrypt, [null].concat(args)))();
};

module.exports.generateKey = Pemcrypt.generateKey.bind(Pemcrypt);
