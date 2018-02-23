const assert = require("assert"),
    should = require('should'),
    should_http = require('should-http');

describe("JWT-KMS", function()
{
    var jwtkms = null,
        created_signing_key = null,
        public_key = "my secret",
        token = null;

    it("should take a test arn in an ENV variable", function(done)
    {
        process.env.should.have.property("KEY_ARN");

        done();
	});
	
	it("should instantiate an instance with a empty config", function(done)
    {
        jwtkms = new (require("../index.js"))();

		should.exist(jwtkms);

        done();

    });

    it("should instantiate an instance", function(done)
    {
        jwtkms = new (require("../index.js"))({
            aws: {
                region: "us-east-1"
            }
        });

        should.exist(jwtkms);

        done();

    });

    it("should sign a payload", function(done)
    {
        jwtkms.sign({foo: "bar"}, process.env.KEY_ARN).then(function(new_token)
        {
            should.exist(new_token);
            token = new_token;

            done();
        }).catch(function(err){ throw err; });
    });

    it("should verify a token", function(done)
    {
        jwtkms.verify(token).then(function(decoded)
        {
            should.exist(decoded);
            decoded.should.have.property('foo').eql("bar");
            decoded.should.have.property('iat');
            decoded.should.not.have.property('exp');

            done();
        }).catch(function(err){ throw err; });
    });

    it("should sign a payload with expiration date", function(done)
    {
        jwtkms.sign({foo: "bar"}, {expires: new Date(Date.now() + 10000)}, process.env.KEY_ARN).then(function(new_token)
        {
            should.exist(new_token);
            token = new_token;

            done();
        }).catch(function(err){ throw err; });
    });

    it("should verify a token with a valid expiration date", function(done)
    {
        jwtkms.verify(token).then(function(decoded)
        {
            should.exist(decoded);
            decoded.should.have.property('foo').eql("bar");
            decoded.should.have.property('iat');
            decoded.should.have.property('exp');

            done();
        }).catch(function(err){ throw err; });
	});
	
	it("should validate a token", function(done)
    {
		jwtkms.validate(token).should.eql(true);
		done();
	});

    it("should sign a payload with expired expiration date", function(done)
    {
        jwtkms.sign({foo: "bar"}, {expires: new Date(Date.now() - 2000)}, process.env.KEY_ARN).then(function(new_token)
        {
            should.exist(new_token);
            token = new_token;

            done();
        }).catch(function(err){ throw err; });
    });

    it("should not verify an expired token", function(done)
    {
        jwtkms.verify(token).then(function(decoded)
        {
            // Should not get here
        }).catch(function(err){ should.exist(err); done(); });
    });

    it('should not verify an invalid token', function(done)
    {
        var token_parts = token.split(".");

        jwtkms.verify(token_parts[0] + "." + token_parts[1] + "." + "AQICAHh7R1QbF3+WxosbJFTfuTKfFZH+61Oimgx8/bItygMW3wHGbfc1lSutmYpuDg8XqSzOAAAAhjCBgwYJKoZIhvcNAQcGoHYwdAIBADBvBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDHiixPWB67X6kRqPFQIBEIBCcpJ2aHs0Srhzhvd6b2JO9fv63FdihVV8K3BPB7dgOYsxJi8tfLUrDKaHPFhOtHww6CSVgNb62Hh0/1YhUKnl0Gya").then(function(decoded)
        {
            // Should not get here
        }).catch(function(err){ should.exist(err); done(); });
	});
	
	it("should sign a payload that was issued 10 seconds before your local time", function(done)
    {
        jwtkms.sign({foo: "bar"}, {issued_at: new Date(Date.now() + 10000)}, process.env.KEY_ARN).then(function(new_token)
        {
            should.exist(new_token);
            token = new_token;

            done();
        }).catch(function(err){ throw err; });
    });

    it("should verify a token that was issued 10 seconds before your local time", function(done)
    {
        jwtkms.verify(token).then(function(decoded)
        {
            should.exist(decoded);
            decoded.should.have.property('foo').eql("bar");
            decoded.should.have.property('iat');

            done();
        }).catch(function(err){ throw err; });
	});

	it("should verify a token wthat was issued 10 seconds before your local time", function(done)
    {
        jwtkms.verify(token).then(function(decoded)
        {
            should.exist(decoded);
            decoded.should.have.property('foo').eql("bar");
            decoded.should.have.property('iat');

            done();
        }).catch(function(err){ throw err; });
	});

	it("should sign a payload that was issued 1 hour before your local time", function(done)
    {
        jwtkms.sign({foo: "bar"}, {issued_at: new Date(Date.now() + 60*60*1000)}, process.env.KEY_ARN).then(function(new_token)
        {
            should.exist(new_token);
            token = new_token;

            done();
        }).catch(function(err){ throw err; });
    });
	
	it("should not verify a token that was issued 1 hour before your local time", function(done)
    {
        jwtkms.verify(token).then(function(decoded)
        {
            // Should not get here
        }).catch(function(err){ should.exist(err); done(); });
	});

	it("should not validate a token that is expired", function(done)
    {
		jwtkms.validate(token).should.eql(false);
		done();
	});

	it("should validate a token that can't be decoded", function(done)
    {
		jwtkms.validate("BLAH BLAH").should.eql(false);
		done();
	});
	
	it("should throw a friendly error if passed a token that can't be decoded", function(done)
    {
        jwtkms.verify("FOO_BAR").then(function(decoded)
        {
            // Should not get here
		}).catch(function(err)
		{ 
			should.exist(err); 
			err.should.eql("Invalid token");
			
			jwtkms.verify("foo.bar.error").then(function(decoded)
			{
				// Should not get here
			}).catch(function(err)
			{ 
				should.exist(err); 
				err.should.eql("Invalid token");
				done();
			});
		});
    });


});