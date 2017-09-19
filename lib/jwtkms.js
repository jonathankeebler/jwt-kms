const AWS = require("aws-sdk"),
    JWT = require("jsonwebtoken");

class JWTKMS
{
    constructor(options) 
    {
        this.kms = new AWS.KMS(options.aws);
        this.key_arm = options.key_arm;
    }

    create_signing_key(public_key, next = () => {})
    {
        return new Promise((resolve, reject) => {
            
            this.kms.encrypt({
                Plaintext: public_key,
                KeyId: this.key_arm
            }, function(err, data)
            {
                if(err) return reject(err);
                return resolve(data.CiphertextBlob.toString("base64"));
            });

        });
    }

    sign(payload, key, next = () => {})
    {
        return new Promise((resolve, reject) => {

            JWT.sign(payload, key, function(err, token)
            {
                if(err) return reject(err);
                resolve(token);          
            });
        });
    }

    verify(token, public_key, next = () => {})
    {
        return new Promise((resolve, reject) => {

            JWT.verify(token, public_key, function(err, decoded)
            {
                if(err) return reject(err);
                resolve(decoded);
            });
        });
        
    }

}

module.exports = JWTKMS;