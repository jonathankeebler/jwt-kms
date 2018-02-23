# JWT-KMS

Sign and validate JWT tokens using keys stored in the AWS Key Management Service (KMS). 

Feature Todo List:
- <strike>Symmetric encryption (both parties have IAM access to KMS key)</strike>
- Asymmetic encryption (only 1 party has IAM access to KMS key)

## Requirements
- node.js 6+

## Installation
```sh
npm install jwt-kms
```

## Usage

```js
const JWTKMS = require("jwt-kms");

var jwtkms = new JWTKMS({
    aws: {
        region: "us-east-1",
        accessKeyId : process.env.AWS_ACCESS_KEY,	// Optional if set in environment
        secretAccessKey: process.env.AWS_SECRET_KEY	// Optional if set in environment
    }
});

// Create a JWT token using a KMS key identified by a key_arn
jwtkms.sign({foo: "bar"}, key_arn).then(function(token)
{
    // ...
});

// Create a JWT token using a KMS key identified by a key_arn
jwtkms.sign(
    { foo: "bar" }, 
    { expires: new Date(Date.now() + 60*1000) }, // Expires in 60 seconds
    key_arn
).then(function(token)
{
    // ...
});

// Verify that you have a valid JWT key
jwtkms.verify(token).then(function(decoded)
{
    console.log(decoded);
    /* 
    {
        foo: "bar
    }
    */
});

// Validate that you have a JWT key but **DOESN'T CHECK FOR AUTHENTICITY**
jwtkms.validate(token);
// true

jwtkms.validate("Not a JWT token");
// false

jwtkms.validate(expired_token);
// false

// This is why you need to use jwtkms.verify to check a token
jwtkms.validate(token_but_not_authentic);
// true

```

## Testing

```sh
npm install mocha -g # if you don't have it installed already
npm test
```

## Credit 

- Created by  [Jonathan Keebler](http://www.keebler.net)
- Inspired by [kms-jwt](https://github.com/bombbomb/kms-jwt)
