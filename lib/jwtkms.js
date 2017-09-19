const AWS = require("aws-sdk"),
    base64url = require("base64url");

class JWTKMS
{
    constructor(options) 
    {
        this.kms = new AWS.KMS(options.aws);
    }

    sign(payload, key_arn)
    {
        return new Promise((resolve, reject) => {

            var headers = {
                alg: "KMS",
                typ: "JWT"
            };

            var token_components = {
                header: base64url( JSON.stringify(headers) ),
                payload: base64url( JSON.stringify(payload) ),
            };

            this.kms.encrypt({
                Plaintext: new Buffer(token_components.header + "." + token_components.payload, "base64"),
                KeyId: key_arn
            }, function(err, data)
            {
                if(err) return reject(err);

                token_components.signature = data.CiphertextBlob.toString("base64");

                var token = token_components.header + "." + token_components.payload + "." + token_components.signature;

                return resolve(token);
            });
        });
    }

    verify(token)
    {
        return new Promise((resolve, reject) => {

            var token_components = token.split(".");

            var header = JSON.parse(base64url.decode(token_components[0]));
            var payload = JSON.parse(base64url.decode(token_components[1]));
            var encrypted_signature = token_components[2];

            var key_arn = header.kid;

            this.kms.decrypt({
                CiphertextBlob: new Buffer(encrypted_signature, "base64")
            }, function(err, data)
            {
                if(err) return reject(err);

                var decrypted_signature = data.Plaintext.toString("base64");

                if(decrypted_signature == token_components[0] + token_components[1])
                {
                    return resolve(payload);    
                }
                else
                {
                    return reject(new Error("Signature wasn't valid"));
                }
            });
        });
        
    }

}

module.exports = JWTKMS;