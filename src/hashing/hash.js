var bcrypt = require('bcrypt');
var crypto = require('crypto');
var scmp = require('scmp');

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
		catch (e) {
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
			if (e) {
				return callback(e);
			}

			callback(null, scmp(hashedToken, hash));
		});
	};

	Hash.prototype.comparePassword = function (password, hash, callback) {
		bcrypt.compare(password, hash, callback);
	};

	Hash.prototype.genereateToken = function (size, callback) {
		if (callback === undefined) {
			callback = size;
			size = 128;
		}

		/**
		 * This code is necessary due to:
		 * https://github.com/Sagacify/sgs-crypto/issues/2
		 */
		if (typeof size !== 'number') {
			return callback(
				new Error(
					'https://github.com/Sagacify/sgs-crypto/issues/2'
				)
			);
		}

		/**
		 * This code is necessary due to:
		 * https://github.com/Sagacify/sgs-crypto/issues/1
		 */
		if (size === 0) {
			return callback(
				new Error(
					'https://github.com/Sagacify/sgs-crypto/issues/1'
				)
			);
		}

		crypto.randomBytes(size, function (e, buffer) {
			if (e) {
				return callback(e);
			}

			callback(null, buffer.toString('hex'));
		});
	};

	return Hash;

})();
