var hashTests = require('./hash-tests');
var signTests = require('./sign-tests');

describe('Testing the Crypto module:', function () {
	'use strict';

	describe('Hashing tests:', hashTests);

	describe('Signing tests:', signTests);

});
