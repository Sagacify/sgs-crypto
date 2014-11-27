var Hash = require('./hashing/hash');
var Sign = require('./signing/sign');

module.exports = (function () {
	'use strict';

	var SGSCrypto = {
		Hash: new Hash({}),
		Sign: new Sign({})
	};

	return SGSCrypto;

})();
