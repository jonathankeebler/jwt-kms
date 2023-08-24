import assert from 'assert';
import should from 'should';
import JWTKMS from '../index.js';

describe("JWT-KMS", function()
{
    let jwtkms = null,
        token = null;

    it("should take a test arn in an ENV variable", function() {
        process.env.should.have.property("KEY_ARN");
	});

	it("should instantiate an instance with a empty config", function() {
        jwtkms = new JWTKMS();
		should.exist(jwtkms);
    });

    it("should instantiate an instance", function() {
        jwtkms = new JWTKMS({
            aws: {
                region: "us-east-1",
                profile: "nova-dev"
            }
        });

        should.exist(jwtkms);

    });

    it("should sign a payload", async function() {
        const new_token = await jwtkms.sign({foo: "bar"}, process.env.KEY_ARN);
        should.exist(new_token);
        token = new_token;
    });

    it("should verify a token", async function() {
        const decoded = await jwtkms.verify(token);
        should.exist(decoded);
        decoded.should.have.property('foo').eql("bar");
        decoded.should.have.property('iat');
        decoded.should.not.have.property('exp');
    });

    it("should sign a payload with expiration date", async function() {
        const new_token = await jwtkms.sign({foo: "bar"}, {expires: new Date(Date.now() + 10000)}, process.env.KEY_ARN);
        should.exist(new_token);
        token = new_token;
    });

    it("should verify a token with a valid expiration date", async function() {
        const decoded = await jwtkms.verify(token);
        should.exist(decoded);
        decoded.should.have.property('foo').eql("bar");
        decoded.should.have.property('iat');
        decoded.should.have.property('exp');
	});

	it("should validate a token", async function() {
		jwtkms.validate(token).valid.should.eql(true);
	});

    it("should sign a payload with expired expiration date", async function() {
        const new_token = await jwtkms.sign({foo: "bar"}, {expires: new Date(Date.now() - 2000)}, process.env.KEY_ARN)
        should.exist(new_token);
        token = new_token;
    });

    it("should not verify an expired token", async function() {
        try {
            const decoded = await jwtkms.verify(token)
            assert(false);
        } catch(err) {
            should.exist(err);
        }
    });

    it('should not verify an invalid token', async function()
    {
        const token_parts = token.split(".");
        try {
            const decoded = await jwtkms.verify(token_parts[0] + "." + token_parts[1] + "." + "AQICAHh7R1QbF3+WxosbJFTfuTKfFZH+61Oimgx8/bItygMW3wHGbfc1lSutmYpuDg8XqSzOAAAAhjCBgwYJKoZIhvcNAQcGoHYwdAIBADBvBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDHiixPWB67X6kRqPFQIBEIBCcpJ2aHs0Srhzhvd6b2JO9fv63FdihVV8K3BPB7dgOYsxJi8tfLUrDKaHPFhOtHww6CSVgNb62Hh0/1YhUKnl0Gya");
            assert(false);
        } catch(err) {
            should.exist(err);
        }
	});

	it("should sign a payload that was issued 10 seconds before your local time", async function()
    {
        const new_token = await jwtkms.sign({foo: "bar"}, {issued_at: new Date(Date.now() + 10000)}, process.env.KEY_ARN);
        should.exist(new_token);
        token = new_token;
    });

    it("should verify a token that was issued 10 seconds before your local time", async function()
    {
        const decoded = await jwtkms.verify(token);
        should.exist(decoded);
        decoded.should.have.property('foo').eql("bar");
        decoded.should.have.property('iat');

    });

	it("should verify a token wthat was issued 10 seconds before your local time", async function()
    {
        const decoded = await jwtkms.verify(token);
        should.exist(decoded);
        decoded.should.have.property('foo').eql("bar");
        decoded.should.have.property('iat');

    });

	it("should sign a payload that was issued 1 hour before your local time", async function()
    {
        const new_token = await jwtkms.sign({foo: "bar"}, {issued_at: new Date(Date.now() + 60*60*1000)}, process.env.KEY_ARN);
        should.exist(new_token);
        token = new_token;

    });

	it("should not verify a token that was issued 1 hour before your local time", async function()
    {
        try {
            const decoded = await jwtkms.verify(token);
            assert(false);
        } catch(err) {
            should.exist(err);
        }});

	it("should not validate a token that is expired", function()
    {
		jwtkms.validate(token).valid.should.eql(false);
	});

	it("should validate a token that can't be decoded", function()
    {
		jwtkms.validate("BLAH BLAH").valid.should.eql(false);
	});

	it("should throw a friendly error if passed a token that can't be decoded", async function()
    {
        try {
            const decoded = await jwtkms.verify("FOO_BAR");
            assert(false);
        } catch (err) {
            should.exist(err);
            err.message.should.eql("Invalid token");
        }
    });


});
