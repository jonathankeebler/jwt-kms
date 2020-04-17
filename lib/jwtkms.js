const AWS = require("aws-sdk"),
    base64url = require("base64url");

class JWTKMS {
    constructor(options) {
        if (!options) {
            options = {
                aws: {
                    region: "us-east-1"
                }
            };
        }

        this.kms = new AWS.KMS(options.aws);
        this.awsmapping = {
            "RS256": 'RSASSA_PKCS1_V1_5_SHA_256',
            "RS384": 'RSASSA_PKCS1_V1_5_SHA_384',
            "RS512": 'RSASSA_PKCS1_V1_5_SHA_512',
            "ES256": 'ECDSA_SHA_256',
            "ES384": 'ECDSA_SHA_384',
            "ES512": 'ECDSA_SHA_512',
        }

    }

    sign(payload, options) {

        return new Promise((resolve, reject) => {

            if (!options.keyId)
                reject("KeyId not provived");

            if (!options.algorithm)
                reject("algorithm not provided");

            let key_arn = options.keyId;

            let valid_algs = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]

            if (!valid_algs.includes(options.algorithm))
                reject("Invalid algoritm");

            var headers = {
                alg: options.algorithm,
                typ: "JWT"
            };

            if (options.issued_at && options.issued_at instanceof Date) {
                payload.iat = Math.ceil(options.issued_at.getTime() / 1000);
            } else if (!payload.iat) {
                payload.iat = Math.floor(Date.now() / 1000);
            }

            if (options.expires && options.expires instanceof Date) {
                payload.exp = Math.ceil(options.expires.getTime() / 1000);
            }

            var token_components = {
                header: base64url(JSON.stringify(headers)),
                payload: base64url(JSON.stringify(payload)),
            };


            try {
                this.kms.describeKey({ KeyId: key_arn }, (err, data) => {
                    if (err) {
                        console.log("Invalid key");
                        reject(err);
                    } else {

                        let params = {
                            KeyId: key_arn,
                            Message: Buffer.from(token_components.header + "." + token_components.payload),
                            SigningAlgorithm: this.awsmapping[options.algorithm],
                            MessageType: "RAW"
                        };

                        try {
                            this.kms.sign(params, function(err, data) {
                                if (err) return reject(err);

                                token_components.signature = base64url(data.Signature);

                                var token = token_components.header + "." + token_components.payload + "." + token_components.signature;

                                return resolve(token);
                            });
                        } catch (err) {
                            reject(err);
                        }
                    }
                });

            } catch (err) {
                reject(err);
            }

        });
    }

    validate(token, next) {

        var reply = function(err, encrypted_signature) {
            if (next) {
                return next(err, encrypted_signature);
            } else {
                return !err;
            }
        }

        if (!token || !token.split) return reply("Invalid token");

        var token_components = token.split(".");

        if (token_components.length !== 3) {
            return reply("Invalid token");
        }

        var components = {

        };

        try {
            components.header = JSON.parse(base64url.decode(token_components[0]));
            components.payload = JSON.parse(base64url.decode(token_components[1]));
            components.encrypted = {
                header: token_components[0],
                payload: token_components[1],
                signature: token_components[2]
            };
        } catch (err) {
            return reply("Invalid token");
        }


        if (components.payload.iat) {
            var issued_at = new Date(components.payload.iat * 1000 - 10 * 60 * 1000); // Allow for server times that are 10 mins ahead of the local time

            if (issued_at >= new Date()) {
                return reply("Token was issued after the current time");
            }
        }

        if (components.payload.exp) {
            var expires_at = new Date(components.payload.exp * 1000);

            if (expires_at < new Date()) {
                return reply("Token is expired");
            }
        }

        return reply(null, components);
    }



    verify(token, key_arn) {
        return new Promise((resolve, reject) => {

            this.validate(token, function(err, components) {
                if (err) return reject(err);

                let params = {
                    KeyId: key_arn,
                    Message: Buffer.from(components.encrypted.header + "." + components.encrypted.payload),
                    Signature: base64url.toBuffer(components.encrypted.signature),
                    SigningAlgorithm: this.awsmapping[components.header.alg],
                    MessageType: "RAW"
                };

                this.kms.verify(params, function(err, data) {
                    if (err) {
                        return reject("Signature wasn't valid");
                        //return reject(err);
                    }
                    let text = base64url.decode(components.encrypted.payload);
                    resolve(text);
                });
            }.bind(this));


        });

    }

}

module.exports = JWTKMS;