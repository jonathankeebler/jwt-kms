# JWT-KMS

Sign and validate JWT tokens using keys stored in the AWS Key Management Service (KMS). 

This library uses the AWS SDK V3 library

## Requirements
- node.js 14+

## Installation
```sh
npm install jwt-kms-v3
```

## Usage

```js
import JWTKMS from 'jwt-kms';

const jwtkms = new JWTKMS({
    aws: {
        region: "us-east-1",
        accessKeyId : process.env.AWS_ACCESS_KEY,	// Optional if set in environment
        secretAccessKey: process.env.AWS_SECRET_KEY	// Optional if set in environment
    }
});

// Create a JWT token using a KMS key identified by a key_arn
const token = await jwtkms.sign({foo: "bar"}, key_arn);
// ...

// Create a JWT token using a KMS key identified by a key_arn
const token = await jwtkms.sign(
    { foo: "bar" }, 
    { expires: new Date(Date.now() + 60*1000) }, // Expires in 60 seconds
    key_arn
);
// ...

// Verify that you have a valid JWT key
const decoded = await jwtkms.verify(token);
    console.log(decoded);
    /* 
    {
        foo: "bar
    }
    */

// Validate that you have a JWT key but **DOESN'T CHECK FOR AUTHENTICITY**
jwtkms.validate(token);
// { components, valid: true}

jwtkms.validate("Not a JWT token");
// { error: 'Invalid token' valid: false }

jwtkms.validate(expired_token);
// { error: 'Token expired' valid: false }

// This is why you need to use jwtkms.verify to check a token
jwtkms.validate(token_but_not_authentic);
// { components, valid: true}

```

## Testing

```sh
npm install 
npm test
```

## Credit 

- Created by  [Kevin Wicken](https://github.com/wicken)
- Inspired by [Jonathan Keebler](http://www.keebler.net)
