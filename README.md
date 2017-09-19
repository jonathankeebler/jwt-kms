# JWT-KMS

Sign and validate JWT tokens using keys stored in the AWS Key Management Service (KMS).

## Requirements
- node.js 6+

## Installation
```sh
npm install jonathankeebler/jwt-kms
```

## Usage

```js
const JWTKMS = require("jwt-kms");

var jwtkms = new JWTKMS({
    aws: {
        region: "us-east-1",
        accessKeyId : process.env.AWS_ACCESS_KEY,
        secretAccessKey: process.env.AWS_SECRET_KEY
    },
    key_arm: process.env.KEY_ARM
});

// Create a signing key
jwtkms.create_signing_key(public_key).then(function(signing_key)
{
    // ...
});

// Create a JWT token using the signing key
jwtkms.sign({foo: "bar"}, signing_key).then(function(token)
{
    // ...
});

// Verify that a JWT token was created with the signing key
jwtkms.verify(token, signing_key).then(function(decoded)
{
    console.log(decoded);
    /* 
    {
        foo: "bar
    }
    */
});

```

## Testing

```sh
npm install mocha -g # if you don't have it installed already
npm test
```
