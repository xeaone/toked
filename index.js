'use strict';

const Util = require('util');
const Jwt = require('jsonwebtoken');

const JwtSign = Util.promisify(Jwt.sign);
const JwtVerify = Util.promisify(Jwt.verify);

module.exports = class Toked {

	constructor (options) {
		options = options || {};
		this.secret = options.secret || null;
		this.realm = options.realm || 'secure';
		this.scheme = options.scheme || 'bearer';
	}

	async strategy (context, encoded, options) {
		const self = this;
		const secret = options.secret || this.secret;

		if (!secret) {
			return { valid: false, message: 'auth toked secret required' };
		}

		try {
			const decoded = await JwtVerify(encoded, secret);
			return { valid: true, credential: { decoded, encoded } };
		} catch (error) {
			if (error.name === 'TokenExpiredError' || error.name === 'JsonWebTokenError') {
				return { valid: false, message: error.message };
			} else {
				throw error;
			}
		}

	}

	async create (user, secret, options) {
		secret = secret || this.secret;

		if (!user) throw new Error('toked user required');
		if (!secret) throw new Error('toked secret required');

		const token = await JwtSign(user, secret, options);

		return token;
	}

}
