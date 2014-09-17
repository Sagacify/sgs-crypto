var bcrypt = require('bcrypt');
var crypto = require('crypto');

module.exports = (function () {
	'use strict';

	function Hash (config) {

		this.config = config || {};

	}

	Hash.prototype.hashToken = function (token, callback) {
		var hashedToken;

		try {
			hashedToken = crypto
			.createHash('sha256')
			.update(token)
			.digest('hex');
		}
		catch(e) {
			return callback(e);
		}

		return callback(null, hashedToken);
	};

	Hash.prototype.hashPassword = function (password, callback) {
		bcrypt.genSalt(function (e, salt) {
			if (e) {
				return callback(e);
			}

			bcrypt.hash(password, salt, callback);
		});
	};

	Hash.prototype.compareToken = function (token, hash, callback) {
		this.hashToken(token, function (e, hashedToken) {
			if(e) {
				return callback(e);
			}

			callback(null, hashedToken === hash);
		});
	};

	Hash.prototype.comparePassword = function (password, hash, callback) {
		bcrypt.compare(password, hash, callback);
	};

	Hash.prototype.genereateToken = function (size, callback) {
		if(callback === undefined) {
			callback = size;
			size = 128;
		}

		crypto.randomBytes(size, function (e, buffer) {
			if (e) {
				return callback(e);
			}

			callback(e, buffer.toString('hex'));
		});
	};

	return Hash;

})();
