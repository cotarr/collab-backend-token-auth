'use strict';
//
//  collab-backend-token-auth
//
// ------------------------------

const fetch = require('node-fetch');

/**
 *  @type {Array} tokenCache - Array of cached tokens
 */
const tokenCache = [];

// ------------------------
// Module Configuration
// ------------------------
/** @type {string} authURL - Authorization server URL */
let authURL = null;
/** @type {string} clientId */
let clientId = null;
/** @type {string} clientSecret */
let clientSecret = null;
/** @type {number} tokenCacheSeconds */
let tokenCacheSeconds = 60;
/** @type {number} tokenCacheCleanSeconds */
let tokenCacheCleanSeconds = 300;

/**
 * Remove expired cached tokens (internal timer handler)
 */
const _removeExpiredCachedTokens = () => {
  if (tokenCache.length > 0) {
    for (let i = tokenCache.length - 1; i >= 0; i--) {
      if ((tokenCache[i].introspect.exp < Math.floor(Date.now() / 1000)) ||
        (tokenCache[i].cacheExpires < new Date())) {
        // console.log('Removing expired token at ' + i.toString());
        tokenCache.splice(i, 1);
      }
    }
  }
  // At startup called first time in authInit();
  setTimeout(_removeExpiredCachedTokens, tokenCacheCleanSeconds * 1000);
};

/**
 * Initialize global variables
 * @param {Object} optionsObj - Module configuration data
 * @param {string} optionsObj.authURL - Authorization server URL
 * @param {string} optionsObj.clientId
 * @param {string} optionsObj.clientSecret
 * @param {number} optionsObj.tokenCacheSeconds
 * @param {number} optionsObj.tokenCacheCleanSeconds
 * @throws Will throw error for missing arguments
 */
const authInit = (optionsObj) => {
  let options = optionsObj;
  if (options == null) options = {};
  if (('authURL' in options) &&
    (typeof options.authURL === 'string') &&
    (options.authURL.length > 0)) {
    authURL = options.authURL;
  } else {
    throw new Error('token-check, invalid authURL in options');
  }
  if (('clientId' in options) &&
    (typeof options.clientId === 'string') &&
    (options.clientId.length > 0)) {
    clientId = options.clientId;
  } else {
    throw new Error('token-check, invalid clientId in options');
  }
  if (('clientSecret' in options) &&
    (typeof options.clientSecret === 'string') &&
    (options.clientSecret.length > 0)) {
    clientSecret = options.clientSecret;
  } else {
    throw new Error('token-check, invalid clientSecret in options');
  }
  if ('tokenCacheSeconds' in options) {
    tokenCacheSeconds = parseInt(options.tokenCacheSeconds);
  }
  if ('tokenCacheCleanSeconds' in options) {
    tokenCacheCleanSeconds = parseInt(options.tokenCacheCleanSeconds);
  }
  // unless token cache is disabled, restart it for first prune cycle
  if (tokenCacheSeconds !== 0) {
    setTimeout(_removeExpiredCachedTokens, tokenCacheCleanSeconds * 1000);
  }
};

// --------------------
// Internal Functions
// --------------------

/**
 * Extract token from http header with input validation
 * @param {Object} req - Node request object
 * @param {Object} chain - chain object passes access token and metadata
 * @param {Object} chain.options
 * @param {string|string[]} chain.options.scope - Token scope restrictions
 * @param {string} chain.accessToken - Oauth 2.0 JWT access token
 * @param {Object} chain.introspect - Decoded token metadata
 * @returns {Promise} Resolved with chain object, or reject with error
 */
const _extractTokenFromHeader = (req, chain) => {
  if (req.headers) {
    if (('authorization' in req.headers) && (typeof req.headers.authorization === 'string')) {
      const authHeaderArray = req.headers.authorization.split(' ');
      if ((authHeaderArray.length === 2) &&
        (authHeaderArray[0].toLowerCase() === 'bearer') &&
        (authHeaderArray[1].length > 0) &&
        // JWT token "xxxxxx.xxxxxx.xxxxx"
        (authHeaderArray[1].split('.').length === 3)) {
        chain.accessToken = authHeaderArray[1];
        return Promise.resolve(chain);
      } else {
        const err = new Error('Expected Bearer token');
        err.status = 401;
        return Promise.reject(err);
      }
    } else {
      const err = new Error('No authorization header');
      err.status = 401;
      return Promise.reject(err);
    }
  } else {
    const err = new Error('Headers not found in req object');
    return Promise.reject(err);
  }
};

/**
 * Lookup access token to return cached token meta-data
 * @param {Object} chain - chain object passes access token and metadata
 * @param {Object} chain.options
 * @param {string|string[]} chain.options.scope - Token scope restrictions
 * @param {string} chain.accessToken - Oauth 2.0 JWT access token
 * @param {Object} chain.introspect - Decoded token metadata
 * @returns {Promise} Resolved with chain object
 */
const _findCachedToken = (chain) => {
  if ((chain) && (chain.accessToken)) {
    // If not cache disabled (seconds = 0), lookup the token
    if (tokenCacheSeconds > 0) {
      const found = tokenCache.find((storedToken) => {
        return (
          // storedToken is found
          (storedToken.token === chain.accessToken) &&
          // Token is "active" state from auth server
          (storedToken.introspect.active) &&
          // Access-token not expired
          (storedToken.introspect.exp > Math.floor(Date.now() / 1000)) &&
          // Cache entry not expired
          (storedToken.cacheExpires > new Date())
        );
      });
      if (found) {
        // console.log('Access token found in tokenCache');
        // found, return authorization metadata
        chain.introspect = found.introspect;
        return Promise.resolve(chain);
      } else {
        // console.log('Access token not found in tokenCache');
        // not found in cache, return null
        chain.introspect = null;
        return Promise.resolve(chain);
      }
    } else {
      // cache disabled, return false
      chain.introspect = null;
      return Promise.resolve(chain);
    }
  } else {
    // access token not in chain, skip
    chain.introspect = null;
    return Promise.resolve(chain);
  }
};

/**
 * Send token to authorization server for validation returning token meta-data
 * @param {Object} chain - chain object passes access token and metadata
 * @param {Object} chain.options
 * @param {string|string[]} chain.options.scope - Token scope restrictions
 * @param {string} chain.accessToken - Oauth 2.0 JWT access token
 * @param {Object} chain.introspect - Decoded token metadata
 * @throws Throws error on fetch network request failure
 * @returns {Object} return chain object
 */
const _validateToken = (chain) => {
  // Check for cached token, if valid token from cache, return it.
  if ((chain) && (chain.accessToken) && (chain.introspect) &&
    (chain.introspect.cached) && (chain.introspect.active)) {
    // console.log('validate cached, skipping fetch');
    return chain;
  } else {
    // Else, not cached, send access token to authorization server for validation
    const clientAuth = Buffer.from(clientId + ':' + clientSecret).toString('base64');
    const body = {
      access_token: chain.accessToken
    };
    const fetchOptions = {
      method: 'POST',
      timeout: 5000,
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        Authorization: 'Basic ' + clientAuth
      },
      body: JSON.stringify(body)
    };
    const authServerUrl = authURL + '/oauth/introspect';
    // Return the Promise
    return fetch(authServerUrl, fetchOptions)
      .then((response) => {
        if (response.ok) {
          return response.json();
        } else {
          if (parseInt(response.status) === 401) {
            // If access-token not found or invalid, authorization server will return status 401
            const err = new Error('Auth server returned 401 Unauthorized');
            err.status = 401;
            throw err;
          } else {
            // Else, not 401, so this is a fetch error from auth server, will return status 500
            throw new Error('Fetch status ' + response.status + ' ' +
            fetchOptions.method + ' ' + authServerUrl);
          }
        }
      })
      .then((responseJson) => {
        // console.log('responseJson ' + JSON.stringify(responseJson, null, 2));
        chain.introspect = responseJson;
        return chain;
      });
    // Fetch error trapped at end of promise chain
  }
};

/**
 * Confirm token is active=true, therefore valid
 * @param {Object} chain - chain object passes access token and metadata
 * @param {Object} chain.options
 * @param {string|string[]} chain.options.scope - Token scope restrictions
 * @param {string} chain.accessToken - Oauth 2.0 JWT access token
 * @param {Object} chain.introspect - Decoded token metadata
 * @returns {Promise} Resolved with chain object, or reject with error
 */
const _checkTokenActive = (chain) => {
  if ((chain) && (chain.accessToken) && (chain.introspect) &&
    (chain.introspect.active) && (chain.introspect.client)) {
    // console.log('checkTokenActive successful');
    return Promise.resolve(chain);
  } else {
    const err = new Error('Error, fetched inactive token');
    err.status = 401;
    return Promise.reject(err);
  }
};

/**
 * Cache token meta-data to service future requests
 * @param {Object} chain - chain object passes access token and metadata
 * @param {Object} chain.options
 * @param {string|string[]} chain.options.scope - Token scope restrictions
 * @param {string} chain.accessToken - Oauth 2.0 JWT access token
 * @param {Object} chain.introspect - Decoded token metadata
 * @returns {Promise} Resolved with chain object
 */
const _saveTokenToCache = (chain) => {
  // If cache enabled (second != 0), and token not previously cached.
  if (tokenCacheSeconds > 0) {
    if ((chain) && (chain.accessToken) && (chain.introspect) && (!chain.introspect.cached)) {
      // console.log('saving token to tokenCache');
      chain.introspect.cached = true;
      tokenCache.push({
        token: chain.accessToken,
        introspect: chain.introspect,
        cacheExpires: new Date(Date.now() + (tokenCacheSeconds * 1000))
      });
      // console.log('Token saved to cache');
      return Promise.resolve(chain);
    } else {
      // case of cached, skipping
      return Promise.resolve(chain);
    }
  } else {
    // case of cache disabled
    return Promise.resolve(chain);
  }
};

/**
 * Add token scope to node request object
 * @param {Object} req - Node request object
 * @param {Object} chain - chain object passes access token and metadata
 * @param {Object} chain.options
 * @param {string|string[]} chain.options.scope - Token scope restrictions
 * @param {string} chain.accessToken - Oauth 2.0 JWT access token
 * @param {Object} chain.introspect - Decoded token metadata
 * @returns {Promise} Resolved with chain object
 */
const _addTokenScopeToReqObject = (req, chain) => {
  if (!req.locals) req.locals = {};
  if ((chain) && (chain.introspect) && (chain.introspect.scope)) {
    req.locals.tokenScope = chain.introspect.scope || [];
  }
  return Promise.resolve(chain);
};

/**
 * Add token user number to node request object
 * @param {Object} req - Node request object
 * @param {Object} chain - chain object passes access token and metadata
 * @param {Object} chain.options
 * @param {string|string[]} chain.options.scope - Token scope restrictions
 * @param {string} chain.accessToken - Oauth 2.0 JWT access token
 * @param {Object} chain.introspect - Decoded token metadata
 * @returns {Promise} Resolved with chain object
 */
const _addUserIdNumberToReqObject = (req, chain) => {
  if (!req.locals) req.locals = {};
  if ((chain) && (chain.introspect) && (chain.introspect.user) &&
    (chain.introspect.user.number) && (chain.introspect.user.number > 0)) {
    req.locals.userid = parseInt(chain.introspect.user.number);
  }
  return Promise.resolve(chain);
};

/**
 * Optional: Restrict access based on scope or array of scopes
 * @param {Object} req - Node request object
 * @param {Object} chain - chain object passes access token and metadata
 * @param {Object} chain.options
 * @param {string|string[]} chain.options.scope - Token scope restrictions
 * @param {string} chain.accessToken - Oauth 2.0 JWT access token
 * @param {Object} chain.introspect - Decoded token metadata
 * @returns {Promise} Resolved with chain object
 */
const _restrictByScope = (req, chain) => {
  if (chain.options.scope) {
    let scopeFound = false;
    if ((chain.options.scope.length > 0) && (req.locals.tokenScope.length > 0)) {
      chain.options.scope.forEach((scopeString) => {
        if (req.locals.tokenScope.indexOf(scopeString) >= 0) scopeFound = true;
      });
    }
    if (scopeFound) {
      return Promise.resolve(chain);
    } else {
      const err = new Error('Forbidden, token has insufficient scope');
      err.status = 403;
      return Promise.reject(err);
    }
  } else {
    // case of no scope restrictions, accept all
    return Promise.resolve(chain);
  }
};

/**
 * Middleware to enforce access token authorization
 * @example
 * // require access token on all subsequent routes
 * app.use(requireAccessToken());
 * @example
 * // require access token and scope for specific route
 * app.get('/somewhere', requireAccessToken({ scope: 'api.write' }), routeHandler)
 * @param {Object} options
 * @param {string|string[]} options.scope - Scope restrictions
 */
const requireAccessToken = (options) => {
  // Options parser
  const opt = {};
  if (!(options == null) && ('scope' in options)) {
    opt.scope = [];
    if ((typeof options.scope === 'string') && (options.scope.length > 0)) {
      opt.scope.push(options.scope);
    } else if ((Array.isArray(options.scope) && options.scope.length > 0)) {
      options.scope.forEach((scopeString) => {
        if ((typeof scopeString === 'string') && (scopeString.length > 0)) {
          opt.scope.push(scopeString);
        }
      });
    }
  }

  return (req, res, next) => {
    if ((!authURL) || (!clientId) || (!clientSecret)) {
      let err = new Error('Module configuration not found. Did you forget in run authInit() ?')
      return next(err);
    } 
    // Create a new chain object, to be passed between promises.
    const chainObj = {
      options: opt,
      accessToken: null,
      introspect: null
    };
    //
    // Chain of asynchronous promises
    //
    _extractTokenFromHeader(req, chainObj)
      .then((chain) => _findCachedToken(chain))
      .then((chain) => _validateToken(chain))
      .then((chain) => _checkTokenActive(chain))
      .then((chain) => _saveTokenToCache(chain))
      .then((chain) => _addTokenScopeToReqObject(req, chain))
      .then((chain) => _addUserIdNumberToReqObject(req, chain))
      .then((chain) => _restrictByScope(req, chain))
      .then((chain) => { return next(); })
      .catch((err) => {
        console.log(err.message);
        // Case of authorization failures, 401 response
        if ((err.status) && (err.status === 401)) {
          // WWW-Authenticate Response Header rfc2617 Section-3.2.1
          const wwwError =
            'Bearer error="Unauthorized", error_description="Access token denied"';
          return res.set('WWW-Authenticate', wwwError)
            .status(401)
            .send('Unauthorized');
        } else if ((err.status) && (err.status === 403)) {
          // WWW-Authenticate Response Header rfc2617 Section-3.2.1
          const wwwError =
            'Bearer error="Forbidden", error_description="Token has insufficient scope"';
          return res.set('WWW-Authenticate', wwwError)
            .status(403)
            .send('Forbidden, Token has insufficient scope');
        } else {
          // Else, pass error to nodejs error handler
          return next(err);
        }
      });
  };
};

/**
 * Middleware to enforce route specific token scope restrictions
 * @param   {string|string[]} requiredScope - Scope values that will be accepted
 * @example
 * // Require scope for route (requireAccessToken() called previously)
 * router.get('/v1/someRoute',
 *   requireScopeForApiRoute(['api.read', 'api.write', 'api.admin']),
 *   validations.list, controller.list);
 * @throws Throws error on missing argument
 **/
const requireScopeForApiRoute = (requiredScope) => {
  if ((requiredScope == null) ||
    ((typeof requiredScope !== 'string') &&
    (!Array.isArray(requiredScope)))) {
    throw new Error('requireScopeForWebPanel requires string or array');
  }
  if (typeof requiredScope === 'string') {
    requiredScope = [requiredScope];
  }
  // Return Express middleware function.
  return (req, res, next) => {
    let scopeFound = false;
    if ((req.locals) && (req.locals.tokenScope) &&
      (Array.isArray(req.locals.tokenScope))) {
      requiredScope.forEach((scopeString) => {
        if (req.locals.tokenScope.indexOf(scopeString) >= 0) scopeFound = true;
      });
      if (scopeFound) {
        return next();
      } else {
        // Case where bearer token fail /introspect due to denied client allowedScope
        // WWW-Authenticate Response Header rfc2617 Section-3.2.1
        const wwwError =
          'Bearer error="Forbidden", error_description="Access token insufficient scope"';
        return res.set('WWW-Authenticate', wwwError)
          .status(403)
          .send('Status 403, Forbidden, Access token insufficient scope');
      }
    } else {
      const err = new Error('Error, Scope not found in request object');
      return next(err);
    }
  };
};

/**
 * Utility to match arbitrary scope using request object
 * @example
 * // Compare scope, requireAccessToken() called previously
 * if (matchScope(req, 'api.admin')) {
 *   // case of scope match, do some custom stuff
 * }
 * @param   {string|string[]} requiredScope - Scope values that will be accepted
 * @throws Throws error on missing argument
 * @returns {boolean} return true if scope in list, otherwise return false
 */
const matchScope = (req, requiredScope) => {
  if ((requiredScope == null) ||
    ((typeof requiredScope !== 'string') &&
    (!Array.isArray(requiredScope)))) {
    throw new Error('matchScope requires string or array');
  }
  if (typeof requiredScope === 'string') {
    requiredScope = [requiredScope];
  }
  let scopeFound = false;
  if ((req.locals) && (req.locals.tokenScope) &&
    (Array.isArray(req.locals.tokenScope))) {
    requiredScope.forEach((scopeString) => {
      if (req.locals.tokenScope.indexOf(scopeString) >= 0) scopeFound = true;
    });
  } else {
    throw new Error('Error, Scope not found in request object');
  }
  // return result as boolean
  return scopeFound;
};

module.exports = {
  authInit,
  requireAccessToken,
  requireScopeForApiRoute,
  matchScope
};
