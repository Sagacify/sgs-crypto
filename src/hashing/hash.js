var bcrypt = require('bcrypt');
var crypto = require('crypto');

module.exports = (function () {
	'use strict';

	function Hash (config) {

		this.config = config || {};

	}

	Hash.prototype.hashPassword = function (password, callback) {
		bcrypt.genSalt(function (e, salt) {
			if (e) {
				return callback(e);
			}

			bcrypt.hash(password, salt, callback);
		});
	};

	Hash.prototype.compareToken = function (token, hash) {
		return this.hashToken(token) === hash;
	};

	Hash.prototype.comparePassword = function (password, hash, callback) {
		bcrypt.compare(password, hash, callback);
	};

	Hash.prototype.genereateToken = function (callback) {
		crypto.randomBytes(128, function (e, buffer) {
			if (e) {
				return callback(e);
			}

			callback(e, buffer.toString('hex'));
		});
	};

	Hash.prototype.hashToken = function (token) {
		return crypto
		.createHash('sha256')
		.update(token)
		.digest('hex');
	};

	return Hash;

})();
