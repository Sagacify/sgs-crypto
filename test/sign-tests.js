var SGSCrypto = require('./coverage/instrument/src/sgs-crypto');
// var SGSCrypto = require('../src/sgs-crypto');
var sgssign = SGSCrypto.Sign;

var assert = require('assert');
var async = require('async');

module.exports = function () {
	'use strict';

	var privateKey = '74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b';

	describe('HMAC-SHA256 message signing and validating:', function () {

		it('Message is signed', function (callback) {
			var method = 'GET';
			var uri = '/api/test?t=1417099532758';
			var body = {
				hello: 'world',
				world: 'hello'
			};
			sgssign.signHTTPRequest(privateKey, method, uri, body, function (e, signature) {
				if (e) {
					return callback(e);
				}

				assert.deepEqual(typeof signature, 'string');
				callback();
			});
		});

		it('Message signing handles errors', function (callback) {
			var method = 'GET';
			var uri = '/api/test?t=1417099532758';
			sgssign.signHTTPRequest(privateKey, method, uri, undefined, function (e, signature) {
				assert.deepEqual(e instanceof Error, true);
				assert.deepEqual(signature, undefined);
				callback();
			});
		});

		it('Message signature is valid SHA256 hash', function (callback) {
			var method = 'GET';
			var uri = '/api/test?t=1417099532758';
			var body = {
				hello: 'world',
				world: 'hello'
			};
			sgssign.signHTTPRequest(privateKey, method, uri, body, function (e, signature) {
				if (e) {
					return callback(e);
				}

				assert.deepEqual(typeof signature, 'string');
				assert.deepEqual(signature.length, 44);
				assert.notDeepEqual(signature.match(/^[a-zA-Z0-9\=\/]{44}$/), null);
				assert.deepEqual(signature.match(/^[a-zA-Z0-9\=\/]{44}$/)[0], signature);
				callback();
			});
		});

		it('Message has different signature if content varies', function (callback) {
			async.parallel({
				signatureA: function (cb) {
					var method = 'GET';
					var uri = '/api/test?t=1417099532758';
					var body = {
						hello: 'world',
						world: 'hello'
					};
					sgssign.signHTTPRequest(privateKey, method, uri, body, cb);
				},
				signatureB: function (cb) {
					var method = 'GET!';
					var uri = '/api/test?t=1417099532758';
					var body = {
						hello: 'world',
						world: 'hello'
					};
					sgssign.signHTTPRequest(privateKey, method, uri, body, cb);
				}
			}, function (e, results) {
				if (e) {
					return callback(e);
				}

				var signatureA = results.signatureA;
				var signatureB = results.signatureB;

				assert.deepEqual(signatureA.length, signatureB.length);
				assert.notEqual(signatureA, signatureB);
				callback();
			});
		});

		it('Message signature is not a signature of falsy values', function (callback) {
			var method = 'GET';
			var uri = '/api/test?t=1417099532758';
			var body = {
				hello: 'world',
				world: 'hello'
			};
			sgssign.signHTTPRequest(privateKey, method, uri, body, function (e, signature) {
				if (e) {
					return callback(e);
				}

				async.parallel({
					compareUndefinedMethod: function (cb) {
						var method = 'undefined';
						var uri = '/api/test?t=1417099532758';
						var body = {
							hello: 'world',
							world: 'hello'
						};
						sgssign.validateHTTPRequest(signature, privateKey, method, uri, body, cb);
					},
					compareNullMethod: function (cb) {
						var method = 'null';
						var uri = '/api/test?t=1417099532758';
						var body = {
							hello: 'world',
							world: 'hello'
						};
						sgssign.validateHTTPRequest(signature, privateKey, method, uri, body, cb);
					},
					compareUndefinedUri: function (cb) {
						var method = 'GET';
						var uri = 'undefined';
						var body = {
							hello: 'world',
							world: 'hello'
						};
						sgssign.validateHTTPRequest(signature, privateKey, method, uri, body, cb);
					},
					compareNullUri: function (cb) {
						var method = 'GET';
						var uri = 'null';
						var body = {
							hello: 'world',
							world: 'hello'
						};
						sgssign.validateHTTPRequest(signature, privateKey, method, uri, body, cb);
					}
				}, function (e, results) {
					if (e) {
						return callback(e);
					}

					var isUndefinedMethod = results.compareUndefinedMethod;
					var isNullMethod = results.compareNullMethod;
					var isUndefinedUri = results.compareUndefinedUri;
					var isNullUri = results.compareNullUri;

					assert.equal(isUndefinedMethod, false);
					assert.equal(isNullMethod, false);
					assert.equal(isUndefinedUri, false);
					assert.equal(isNullUri, false);
					callback();
				});
			});
		});

		it('Message can be signed and compared with success', function (callback) {
			var method = 'GET';
			var uri = 'null';
			var body = {
				hello: 'world',
				world: 'hello'
			};
			async.waterfall([
				function (cb) {
					sgssign.signHTTPRequest(privateKey, method, uri, body, cb);
				},
				function (signature, cb) {
					sgssign.validateHTTPRequest(signature, privateKey, method, uri, body, cb);
				}
			], function (e, matches) {
				if (e) {
					return callback(e);
				}

				assert.deepEqual(matches, true);
				callback();
			});
		});

	});

};
