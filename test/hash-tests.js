var SGSCrypto = require('./coverage/instrument/src/sgs-crypto');
// var SGSCrypto = require('../src/sgs-crypto');
var sgshash = SGSCrypto.Hash;

var chiSquare = require('chi-square');
var assert = require('assert');
var async = require('async');

module.exports = function () {
	'use strict';

	describe('BCrypt password hashes:', function () {

		it('Password is hashed', function (callback) {
			var password = 'test';
			sgshash.hashPassword(password, function (e, hash) {
				if (e) {
					return callback(e);
				}

				assert.deepEqual(typeof hash, 'string');
				assert.notDeepEqual(hash, password);
				callback();
			});
		});

		it('Password hashing handles errors', function (callback) {
			sgshash.hashPassword(undefined, function (e, hash) {
				assert.deepEqual(e instanceof Error, true);
				assert.deepEqual(hash, undefined);
				callback();
			});
		});

		it('Password hash is valid Bcrypt hash', function (callback) {
			var password = 'test';
			sgshash.hashPassword(password, function (e, hash) {
				if (e) {
					return callback(e);
				}

				assert.deepEqual(typeof hash, 'string');
				assert.deepEqual(hash.length, 60);

				var components = hash.split('$');
				components.shift();

				assert.deepEqual(components.length, 3);

				var version = components[0];
				var rounds = components[1];
				var encrypted = components[2];

				assert.deepEqual(version, '2a');
				assert.deepEqual(+(rounds) > 5, true);
				assert.deepEqual(+(rounds) < 13, true);

				assert.deepEqual(typeof encrypted, 'string');
				assert.deepEqual(encrypted.length, 53);
				assert.notEqual(encrypted.match(/^[a-zA-Z0-9\.\/]{53}$/), null);
				assert.deepEqual(encrypted.match(/^[a-zA-Z0-9\.\/]{53}$/)[0], encrypted);
				callback();
			});
		});

		it('Password has different hash every time', function (callback) {
			var password = 'test';
			async.parallel({
				hashA: function (cb) {
					sgshash.hashPassword(password, cb);
				},
				hashB: function (cb) {
					sgshash.hashPassword(password, cb);
				}
			}, function (e, results) {
				if (e) {
					return callback(e);
				}

				var hashA = results.hashA;
				var hashB = results.hashB;

				assert.deepEqual(hashA.length, hashB.length);
				assert.notEqual(hashA, hashB);
				callback();
			});
		});

		it('Password hash is not a hash of falsy values', function (callback) {
			var password = 'test';
			sgshash.hashPassword(password, function (e, hash) {
				if (e) {
					return callback(e);
				}

				async.parallel({
					compareUndefined: function (cb) {
						sgshash.comparePassword('undefined', hash, cb);
					},
					compareNull: function (cb) {
						sgshash.comparePassword('null', hash, cb);
					},
					compareEmptyString: function (cb) {
						sgshash.comparePassword('', hash, cb);
					}
				}, function (e, results) {
					if (e) {
						return callback(e);
					}

					var isUndefinedHash = results.compareUndefined;
					var isNullHash = results.compareNull;
					var isEmptyStringHash = results.compareEmptyString;

					assert.equal(isUndefinedHash, false);
					assert.equal(isNullHash, false);
					assert.equal(isEmptyStringHash, false);
					callback();
				});
			});
		});

		it('Password can be hashed and compared with success', function (callback) {
			var password = 'test';
			async.waterfall([
				function (cb) {
					sgshash.hashPassword(password, cb);
				},
				function (hash, cb) {
					sgshash.comparePassword(password, hash, cb);
				}
			], function (e, matches) {
				if (e) {
					return callback(e);
				}

				assert.deepEqual(matches, true);
				callback();
			});
		});

		it('Bcrypt has cryptograph. strong randomness', function (callback) {
			this.timeout(10 * 1000);
			var password = 'test';
			var rounds = 100;
			async.times(rounds, function (i, cb) {
				sgshash.hashPassword(password, function (e, hash) {
					if (e) {
						return cb(e);
					}

					var distribution = chiSquare.calculate(new Buffer(hash, 'base64'));
					cb(null, distribution);
				});
			}, function (e, distributions) {
				if (e) {
					return callback(e);
				}

				var sum = distributions.reduce(function (sum, distribution) {
					return sum + distribution;
				}, 0);
				var avg = sum / rounds;

				assert.deepEqual(avg < 0.6, true);
				assert.deepEqual(avg > 0.4, true);
				callback();
			});
		});

	});

	describe('Node.js\'s Crypto core module tokens' , function () {

		it('Token is hashed', function (callback) {
			var token;
			async.waterfall([
				function (cb) {
					sgshash.genereateToken(cb);
				},
				function (resToken, cb) {
					token = resToken;
					sgshash.hashToken(resToken, cb);
				}
			], function (e, hashedToken) {
				if (e) {
					return callback(e);
				}

				assert.deepEqual(typeof hashedToken, 'string');
				assert.notDeepEqual(hashedToken, token);
				callback();
			});
		});

		it('Token hashing handles errors', function (callback) {
			sgshash.hashToken(undefined, function (e, hashedToken) {
				assert.deepEqual(e instanceof Error, true);
				assert.deepEqual(hashedToken, undefined);
				callback();
			});
		});

		it('Token comparison handles errors', function (callback) {
			async.waterfall([
				function (cb) {
					sgshash.genereateToken(cb);
				},
				function (resToken, cb) {
					sgshash.hashToken(resToken, cb);
				},
			], function (e, hashedToken) {
				if (e) {
					return callback(e);
				}

				sgshash.compareToken(undefined, hashedToken, function (e, matches) {
					assert.deepEqual(e instanceof Error, true);
					assert.deepEqual(matches, undefined);
					callback();
				});
			});
		});

		it('Token generation handles errors', function (callback) {
			sgshash.genereateToken(undefined, function (e, hashedToken) {
				assert.deepEqual(e instanceof Error, true);
				assert.deepEqual(hashedToken, undefined);
				callback();
			});
		});

		it('Token generation handles errors', function (callback) {
			sgshash.genereateToken(0, function (e, hashedToken) {
				assert.deepEqual(e instanceof Error, true);
				assert.deepEqual(hashedToken, undefined);
				callback();
			});
		});

		it('Token hash is valid SHA256 hash', function (callback) {
			async.waterfall([
				function (cb) {
					sgshash.genereateToken(cb);
				},
				function (token, cb) {
					sgshash.hashToken(token, cb);
				}
			], function (e, hashedToken) {
				if (e) {
					return callback(e);
				}

				assert.deepEqual(typeof hashedToken, 'string');
				assert.deepEqual(hashedToken.length, 64);
				assert.notDeepEqual(hashedToken.match(/^[a-f0-9]{64}$/), null);
				assert.deepEqual(hashedToken.match(/^[a-f0-9]{64}$/)[0], hashedToken);
				callback();
			});
		});

		it('Token hash is not a hash of falsy values', function (callback) {
			async.waterfall([
				function (cb) {
					sgshash.genereateToken(cb);
				},
				function (token, cb) {
					sgshash.hashToken(token, cb);
				}
			], function (e, hashedToken) {
				if (e) {
					return callback(e);
				}

				async.parallel({
					compareUndefined: function (cb) {
						sgshash.compareToken('undefined', hashedToken, cb);
					},
					compareNull: function (cb) {
						sgshash.compareToken('null', hashedToken, cb);
					},
					compareEmptyString: function(cb) {
						sgshash.compareToken('', hashedToken, cb);
					}
				}, function (e, results) {
					if (e) {
						return callback(e);
					}

					var isUndefinedHash = results.compareUndefined;
					var isNullHash = results.compareNull;
					var isEmptyStringHash = results.compareEmptyString;

					assert.deepEqual(isUndefinedHash, false);
					assert.deepEqual(isNullHash, false);
					assert.deepEqual(isEmptyStringHash, false);
					callback();
				});
			});
		});

		it('Token can be hashed and compared with success', function (callback) {
			var token;
			async.waterfall([
				function (cb) {
					sgshash.genereateToken(cb);
				},
				function (resToken, cb) {
					token = resToken;
					sgshash.hashToken(resToken, cb);
				},
			], function (e, hashedToken) {
				if (e) {
					return callback(e);
				}

				sgshash.compareToken(token, hashedToken, function (e, matches) {
					if (e) {
						return callback(e);
					}

					assert.deepEqual(matches, true);
					callback();
				});
			});
		});

		it('SHA256 has cryptograph. strong randomness', function (callback) {
			this.timeout(10 * 1000);
			var rounds = 100;
			async.times(rounds, function (i, cb) {
				sgshash.genereateToken(function (e, token) {
					if (e) {
						return cb(e);
					}

					var distribution = chiSquare.calculate(new Buffer(token, 'hex'));
					cb(null, distribution);
				});
			}, function (e, distributions) {
				if (e) {
					return callback(e);
				}

				var sum = distributions.reduce(function (sum, distribution) {
					return sum + distribution;
				}, 0);
				var avg = sum / rounds;

				assert.deepEqual(avg < 0.6, true);
				assert.deepEqual(avg > 0.4, true);
				callback();
			});
		});

	});

};
