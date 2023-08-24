import { DecryptCommand, EncryptCommand, KMSClient } from '@aws-sdk/client-kms';

import base64url from 'base64url';
import {GetCallerIdentityCommand, STSClient} from "@aws-sdk/client-sts";

export default class JWTKMS
{
	constructor(config) {
		this.client = new KMSClient(config?.aws);
	}

	async sign(payload, options, key_arn) {
		if (!key_arn) {
			key_arn = options;
			options = {};
		}

		const headers = {
			alg: 'KMS',
			typ: 'JWT',
		};

		if (options.issued_at && options.issued_at instanceof Date) {
			payload.iat = Math.ceil(options.issued_at.getTime() / 1000);
		}
		else if (!payload.iat)
		{
			payload.iat = Math.floor(Date.now() / 1000);
		}

		if (options.expires && options.expires instanceof Date)
		{
			payload.exp = Math.ceil(options.expires.getTime() / 1000);
		}

		const token_components = {
			header: base64url(JSON.stringify(headers)),
			payload: base64url(JSON.stringify(payload)),
		};

		try {
			const data = await this.client.send(new EncryptCommand({
				Plaintext: Buffer.from(base64url(`${token_components.header}.${token_components.payload}`), 'base64'),
				KeyId: key_arn,
			}));
			token_components.signature = Buffer.from(data.CiphertextBlob).toString('base64');
		} catch (err) {
			throw new Error('Failed to sign token');
		}
		return `${token_components.header}.${token_components.payload}.${token_components.signature}`;
	}

	validate(token) {
		const respond = ({error, components}) => ({ error, components, valid: !error });
		if (!token || !token.split) return respond({ error: 'Invalid token' });

		const token_components = token.split('.');

		if (token_components.length !== 3) {
			return respond({ error:'Invalid token'});
		}

		const components = {};

		try {
			components.header = JSON.parse(base64url.decode(token_components[0]));
			components.payload = JSON.parse(base64url.decode(token_components[1]));
			components.encrypted = {
				header: token_components[0],
				payload: token_components[1],
				signature: token_components[2],
			};
		} catch (err) {
			return respond({ error: 'Invalid token'});
		}

		if (components.payload.iat) {
			const issued_at = new Date(components.payload.iat * 1000 - 10 * 60 * 1000); // Allow for server times that are 10 mins ahead of the local time
			if (issued_at >= new Date()) {
				return respond({ error: 'Token was issued after the current time'});
			}
		}

		if (components.payload.exp) {
			const expires_at = new Date(components.payload.exp * 1000);
			if (expires_at < new Date()) {
				return respond({ error: 'Token is expired' });
			}
		}

		return respond({ components });
	}

	async verify(token) {
		const { components, error} = this.validate(token);
		if(error) throw new Error(error);

		const data = await this.client.send(new DecryptCommand({
			CiphertextBlob: new Buffer(components.encrypted.signature, 'base64'),
		}));

		const decrypted_signature = base64url.decode(Buffer.from(data.Plaintext).toString('base64'));
		if (decrypted_signature !== `${components.encrypted.header}.${components.encrypted.payload}`)
		{
			throw new Error('Signature wasn\'t valid');
		}
		return components.payload;
	}
}
