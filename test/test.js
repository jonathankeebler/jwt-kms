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
        process.env.should.have.property("KEY_ARM");

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
        jwtkms.sign({foo: "bar"}, process.env.KEY_ARM).then(function(new_token)
        {
            should.exist(new_token);
            token = new_token;

            done();
        }).catch(function(err){ should.not.exist(err); });
    });

    it("should verify a token", function(done)
    {
        jwtkms.verify(token).then(function(decoded)
        {
            should.exist(decoded);
            decoded.should.have.property('foo').eql("bar");

            done();
        }).catch(function(err){ should.not.exist(err); });
    });


});