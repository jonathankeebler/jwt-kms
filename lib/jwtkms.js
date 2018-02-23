const AWS = require("aws-sdk"),
    base64url = require("base64url");

class JWTKMS
{
    constructor(options) 
    {
		if(!options)
		{
			options = {
				aws: {
					region: "us-east-1"
				}
			};
		}

        this.kms = new AWS.KMS(options.aws);
    }

    sign(payload, options, key_arn)
    {
        if(!key_arn)
        {
            key_arn = options;
            options = {};
        }

        return new Promise((resolve, reject) => {

            var headers = {
                alg: "KMS",
                typ: "JWT"
            };

			if(options.issued_at && options.issued_at instanceof Date )
			{
				payload.iat = Math.ceil( options.issued_at.getTime() / 1000 );
			}
            else if(!payload.iat)
            {
                payload.iat = Math.floor( Date.now() / 1000 );
            }

            if(options.expires && options.expires instanceof Date )
            {
                payload.exp = Math.ceil( options.expires.getTime() / 1000 );
            }

            var token_components = {
                header: base64url( JSON.stringify(headers) ),
                payload: base64url( JSON.stringify(payload) ),
            };

            this.kms.encrypt({
                Plaintext: new Buffer(base64url(token_components.header + "." + token_components.payload), "base64"),
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
	
	validate(token, next)
	{
		var reply = function(err, encrypted_signature)
		{
			if(next)
			{
				return next(err, encrypted_signature);
			}
			else
			{
				return !err;
			}
		}

		if(!token || !token.split) return reply("Invalid token");

		var token_components = token.split(".");

		if(token_components.length !== 3)
		{
			return reply("Invalid token");
		}
		
		var components = {

		};

		try
		{
			components.header = JSON.parse(base64url.decode(token_components[0]));
			components.payload = JSON.parse(base64url.decode(token_components[1]));
			components.encrypted = {
				header: token_components[0],
				payload: token_components[1],
				signature: token_components[2]
			};
		}
		catch(err)
		{
			return reply("Invalid token");
		}
		

		var key_arn = components.header.kid;

		if(components.payload.iat)
		{
			var issued_at = new Date(components.payload.iat * 1000 - 10*60*1000); // Allow for server times that are 10 mins ahead of the local time

			if(issued_at >= new Date())
			{
				return reply("Token was issued after the current time");
			}
		}

		if(components.payload.exp)
		{
			var expires_at = new Date(components.payload.exp * 1000);

			if(expires_at < new Date())
			{
				return reply("Token is expired");
			}
		}

		return reply(null, components);
	}



    verify(token)
    {
        return new Promise((resolve, reject) => {

			this.validate(token, function(err, components)
			{
				if(err) return reject(err);

				this.kms.decrypt({
					CiphertextBlob: new Buffer(components.encrypted.signature, "base64")
				}, function(err, data)
				{
					if(err) return reject(err);
	
					var decrypted_signature = base64url.decode(data.Plaintext.toString("base64"));
					
					if(decrypted_signature == components.encrypted.header + "." + components.encrypted.payload)
					{
						return resolve(components.payload);    
					}
					else
					{
						return reject("Signature wasn't valid");
					}
				});
			}.bind(this));

            
        });
        
    }

}

module.exports = JWTKMS;