var crypto = require('crypto');
var scmp = require('scmp');

module.exports = (function () {
	'use strict';

	function Sign (config) {

		this.config = config || {};

	}

	Sign.prototype._serializeHTTPRequest = function (method, uri, body, callback) {
		if (typeof method !== 'string' || !method) {
			return callback(
				new Error('Sign: Missing HTTP method.')
			);
		}

		if (typeof uri !== 'string' || !uri) {
			return callback(
				new Error('Sign: Missing HTTP URI.')
			);
		}

		if (body == null || typeof body !== 'object') {
			return callback(
				new Error('Sign: Missing HTTP body.')
			);
		}

		var requestData = [
			method,
			uri
		];

		/**
		 * This code is commented due to Twilio and Dropbox security vulnerabilities.
		 */

		// body = body || {};
		// var keys = Object.keys(body).sort();
		// var key;

		// for (var i = 0, len = keys.length; i < len; i++) {
		// 	key = keys[i];
		// 	requestData.push(key);
		// 	requestData.push(body[key]);
		// }

		callback(null, requestData.join(''));
	};

	Sign.prototype.signHTTPRequest = function (privateKey, method, uri, body, callback) {
		this._serializeHTTPRequest(method, uri, body, function (e, serializedHTTPRequest) {
			if (e) {
				return callback(e);
			}

			var bufferedHTTPRequest = new Buffer(serializedHTTPRequest, 'utf8');

			callback(
				null,
				crypto
					.createHmac('sha256', privateKey)
					.update(bufferedHTTPRequest)
					.digest('base64')
			)
		});
	};

	Sign.prototype.validateHTTPRequest = function (signature, privateKey, method, uri, body, callback) {
		this.signHTTPRequest(privateKey, method, uri, body, function (e, selfGeneratedSignature) {
			if (e) {
				return callback(e);
			}

			callback(
				null,
				scmp(
					signature,
					selfGeneratedSignature
				)
			);
		});
	};

	return Sign;

})();
