'use strict';

const Util = require('util');
const Jwt = require('jsonwebtoken');

const JwtSign = Util.promisify(Jwt.sign);
const JwtVerify = Util.promisify(Jwt.verify);

module.exports = class Toked {

	constructor (options) {
		options = options || {};
		this.secret = options.secret || null;
	}

	async strategy (context, encoded, auth) {
		const self = this;

		if (!auth.secret) {
			return { valid: false, message: 'auth secret required' };
		}

		try {
			const decoded = await JwtVerify(encoded, auth.secret, auth.options);
			return { valid: true, credential: { decoded, encoded } };
		} catch (error) {
			if (error.name === 'TokenExpiredError' || error.name === 'JsonWebTokenError') {
				return { valid: false, message: error.message };
			} else {
				throw error;
			}
		}

	}

	async create (user, secret) {
		secret = secret || this.secret;

		if (!user) throw new Error('auth toked user required');
		if (!secret) throw new Error('auth toked secret required');

		const token = await JwtSign(user, secret);

		return token;
	}

}
