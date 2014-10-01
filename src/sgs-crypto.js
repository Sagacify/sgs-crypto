var Hash = require('./hashing/hash');

module.exports = (function () {
	'use strict';

	var SGSAuthentication = {
		Hash: new Hash({})
	};

	return SGSAuthentication;

})();
