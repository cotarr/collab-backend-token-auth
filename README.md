# collab-backend-token-auth

Authentication middleware for collab-auth learning project.

## Description

The project [collab-auth](https://github.com/cotarr/collab-auth) was a learning project 
with documentation [here](https://cotarr.github.io/collab-auth/).
Collab-auth is a custom Oauth 2.0 server that was coded using 
[oauth2orize](https://github.com/jaredhanson/oauth2orize).
The scope of the project was aimed at authentication for a home network or personal server.

The GitHub repository [collab-backend-api](https://github.com/cotarr/collab-backend-api) 
was a mock REST API that was added as part of the collab-auth project 
to demonstrate the use of Oauth 2.0 access tokens to restrict access to a web API.

This npm package <b>collab-backend-token-auth</b> is intended to be used as authentication middleware in the 
collab-backend-api mock REST API.

The implementation of address path names, user, client, and token meta-data is unique to the collab-auth implementation 
of Oauth 2.0, so it is unlikely this repository could serve as a generic Oauth 2.0 middleware. 
However, you may find it interesting.

## Alternatives

If you are looking for something more robust try 
[passport-http-bearer](http://www.passportjs.org/packages/passport-http-bearer/)

## Security Note

* No automated tests are included.
* No formal code review has been performed.
* This was intended as a learning project.

## Requirements

- Format of JWT access tokens compatible with [collab-auth](https://github.com/cotarr/collab-auth.git)
- Developed using Debian 10, Node 14.18.2, Express 4.17.2
- Other environments not tested (This was a learning project)

# Installation

```bash
npm install --save @cotarr/collab-backend-token-auth
```

Alternately, this npm module can be installed as a dependency in the context of it's parent API web server
by cloning the GitHub repository [collab-backend-api](https://github.com/cotarr/collab-backend-api).

# Middleware functions

### authInit(options)

The authInit() function is required to be run during module load to set module configuration variables.
The URL and client credentials are required to contact the authentication server.
Care should be taken to avoid disclosure of the client credentials.
By default, token lookups are cached for 60 seconds. The token cache can be
disabled by setting tokenCacheSeconds to 0. The cache expire time is configurable.

AuthInit options properties:

| Property               | Type   | Example                 | Need     | Comments                   |
| ---------------------- | ------ | ----------------------- | -------- | -------------------------- |
| authURL                | string | "http://127.0.0.1:3500" | required | Authorization Server URL   |
| clientId               | string | "abc123"                | required | Client account credentials |
| clientSecret           | string | "ssh-secret"            | required | Client account credentials |
| tokenCacheSeconds      | number | 60                      | optional | Default 60 sec.            |
| tokenCacheCleanSeconds | number | 300                     | optional | Default 300 sec.           |

### requireAccessToken(options);

The requireAccessToken() function is the primary nodejs/express middleware 
that is used to authorize or deny access. This middleware will parse the http 
authorization header for a bearer token and extract a JWT access token.
The token is submitted to the authorization server /oauth/introspect endpoint 
for validation of the digital signature. User related meta-data is returned. 
Unauthorized requests will generate a status 401 Unauthorized response. 
Successful requests will call the express next() function. 
This function will store the token's scope and other user information 
in the Express req object for use by other middleware.

The requireAccessToken(options) function will accept an optional options object.
If the options object contains a scope parameter, then in addition to a valid
access token, access will require that at least one of the scopes in the access token must match 
one of the scopes specified in the options object. The scope value may be either
a sting or an array of strings.  For example:

```js
// Require valid access token, but with any scope restrictions
app.use(requireAccessToken()); 

// Require both valid access token and token scope to match api.write
app.use(requireAccessToken({ scope: 'api.write' })); 

// Require valid access token, then require either api.read or api.write
app.use(requireAccessToken({ scope: ['api.read', 'api.write'] })); 
```

| Property | Type      | Example                                       | Comments                           |
| -------- | ------    | --------------------------------------------- | ---------------------------------- |
|          | undefined | options = {}                                  | No scope restrictions              |
| scope    | string    | options = { scope: 'api.write' }              | Require scope must match api.write |
| scope    | Array     | options = { scope: ['api.read', 'api.read'] } | Both scopes accepted               |

### requireScopeForApiRoute(scope);

The requireScopeForApiRoute() is a middleware function that is intended to 
be used on a SQL connected server with multiple routes such as a REST API. 
The middleware would allow or deny specific routes depending on the scope 
values of the user who generated the access token.
Requests with insufficient scope will generate a status 403 Forbidden response. 
Successful requests will call the Express next() function. 

The requireAccessToken() middleware MUST be run prior to requireScopeForApiRoute() function.
The requireScopeForApiRoute() will accept either a single string or an array of strings;

### matchScope(scope)

The matchScope() function is a general function that will make a scope determination
and return a boolean true or false. The requireAccessToken() middleware MUST 
be run prior to the matchScope() function.

For more information about scope, refer to the documentation of the collab-auth repository.

## Example

The following example combines all of these functions into a single example for use 
in a backend express web server.

```js
const { authInit, requireAccessToken, requireScopeForApiRoute, matchScope } = require('@cotarr/collab-backend-token-auth');

// On module load, set configuration variables
authInit({
  authURL: process.env.OAUTH2_AUTH_URL,
  clientId: process.env.OAUTH2_CLIENT_ID,
  clientSecret: process.env.OAUTH2_CLIENT_SECRET
});

// This route is access restricted and requires an access token.
app.get('/hello', requireAccessToken(), (req, res) => { res.send('Hello World'); });

// All routes beyond this point require authorization
app.use(requireAccessToken());

// The route /test requires either api.read or api.write
// but will return different content based on scope.
app.get('/test',
  requireScopeForApiRoute(['api.read', 'api.write']),
  (req, res, next) => {
    if (matchScope(req, 'api.write')) {
      res.json({ test: 'Test: scope matches' });
    } else {
      res.json({ test: 'Test: scope not match' });
    }
  }
);
```
