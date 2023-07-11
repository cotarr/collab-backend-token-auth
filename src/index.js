'use strict';
//
//  collab-backend-token-auth
//
// ------------------------------

const crypto = require('node:crypto');

/**
 * Example cache:
 * [
 *   {
 *     token: "xxxxxxx.xxxxxxx.xxxxxxx",
 *     introspect: {
 *        ... token metadata ...
 *     },
 *     cacheExpires: "2023-07-07T17:31:35.057Z"
 *   },
 *   {
 *      ... more tokens ...
 *   }
 * ]
 * @type {Array} tokenCache - Module variable to hold array of cached tokens
 */
const tokenCache = [];

/**
 * Remove expired cached tokens (internal timer handler)
 */
const _removeExpiredCachedTokens = () => {
  if (tokenCache.length > 0) {
    for (let i = tokenCache.length - 1; i >= 0; i--) {
      if ((tokenCache[i].introspect.exp < Math.floor(Date.now() / 1000)) ||
        // Time as javascript Date object
        (tokenCache[i].cacheExpires < new Date())) {
        // console.log('Removing expired token at ' + i.toString());
        tokenCache.splice(i, 1);
      }
    }
  }
  // At startup called first time in authInit();
  setTimeout(_removeExpiredCachedTokens, tokenCacheCleanSeconds * 1000);
};

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
 * Function to be run at program start to initialize module configuration
 * @example
 * authInit({
 *   authURL: 'http://127.0.0.1:3500',
 *   clientId: 'abc123',
 *   clientSecret: 'ssh-secret',
 *   tokenCacheSeconds: 60,
 *   tokenCacheCleanSeconds: 300
 * });
 * @param {Object} optionsObj - Module configuration data
 * @param {string} optionsObj.authURL - Authorization server URL
 * @param {string} options.clientId - Client account credentials
 * @param {string} options.clientSecret - Client account credentials
 * @param {number} optionsObj.tokenCacheSeconds - User's access token trusted for this time.
 * @param {number} optionsObj.tokenCacheCleanSeconds - Prune untrusted user's access tokens.
 * @throws Will throw error for missing arguments
 */
exports.authInit = (options) => {
  if (options == null) {
    throw new Error('authInit requires an options object.');
  }
  if ((Object.hasOwn(options, 'authURL')) &&
    (typeof options.authURL === 'string') &&
    (options.authURL.length > 0)) {
    authURL = options.authURL;
  } else {
    throw new Error('token-check, invalid authURL in options');
  }
  if ((Object.hasOwn(options, 'clientId')) &&
    (typeof options.clientId === 'string') &&
    (options.clientId.length > 0)) {
    clientId = options.clientId;
  } else {
    throw new Error('token-check, invalid clientId in options');
  }
  if ((Object.hasOwn(options, 'clientSecret')) &&
    (typeof options.clientSecret === 'string') &&
    (options.clientSecret.length > 0)) {
    clientSecret = options.clientSecret;
  } else {
    throw new Error('token-check, invalid clientSecret in options');
  }
  if (Object.hasOwn(options, 'tokenCacheSeconds')) {
    tokenCacheSeconds = parseInt(options.tokenCacheSeconds);
  }
  if (Object.hasOwn(options, 'tokenCacheCleanSeconds')) {
    tokenCacheCleanSeconds = parseInt(options.tokenCacheCleanSeconds);
  }
  // unless token cache is disabled, restart it for first prune cycle
  if (tokenCacheSeconds !== 0) {
    setTimeout(_removeExpiredCachedTokens, tokenCacheCleanSeconds * 1000);
  }
};

// -------------------------
// Module Internal Functions
// -------------------------

/**
 * Initialize the chain object.
 * The chain object will be used to hold state related data as it passes down the promise chain.
 * @param {Object} options - argument to requireAccessToken(options) authorization
 * @param {string||string[]} options.scope - Token scope restrictions
 * @returns {Promise} Resolved with a new chain object
 */
const _initChainObject = (options) => {
  if ((authURL == null) || (clientId == null) || (clientSecret == null)) {
    const err = new Error('Module configuration not found. Did you forget in run authInit() ?');
    return Promise.reject(err);
  }
  // Options parser
  const opt = Object.create(null);
  if ((!(options == null)) && (Object.hasOwn(options, 'scope'))) {
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
  // Create a new chain object, to be passed between promises.
  const chainObj = Object.create(null);
  chainObj.options = opt;
  chainObj.accessToken = null;
  chainObj.introspect = null;
  return Promise.resolve(chainObj);
};

/**
 * Extract token from http header with input validation
 * @param {Object} req - Node request object
 * @param {Object} chain - chain object passes access token and metadata
 * @param {Object} chain.options argument to requireAccessToken(options) authorization
 * @param {string|string[]} chain.options.scope - Token scope restrictions
 * @param {string} chain.accessToken - Oauth 2.0 JWT access token
 * @param {Object} chain.introspect - Decoded token metadata
 * @returns {Promise} Resolved with chain object, or reject with error
 */
const _extractTokenFromHeader = (req, chain) => {
  if (req.headers) {
    if ((Object.hasOwn(req.headers, 'authorization')) &&
      (typeof req.headers.authorization === 'string')) {
      // Typical collab-auth token string length 554 bytes
      if (req.headers.authorization.length < 4096) {
        const authHeaderArray = req.headers.authorization.split(' ');
        if ((authHeaderArray.length === 2) &&
          (authHeaderArray[0].toLowerCase() === 'bearer') &&
          (authHeaderArray[1].length > 0) &&
          // JWT token "xxxxxx.xxxxxx.xxxxx"
          (authHeaderArray[1].split('.').length === 3)) {
          // Input validation succeeded, add Bearer token to chain object
          chain.accessToken = authHeaderArray[1];
          return Promise.resolve(chain);
        } else {
          const err = new Error('Expected Bearer token');
          err.status = 401;
          return Promise.reject(err);
        }
      } else {
        const err = new Error('Authorization header exceeds maximum length');
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
    // Internal server error
    err.status = 500;
    return Promise.reject(err);
  }
};
/**
 * Timing safe compare for two access tokens
 * @param   {String} token1 - Access token
 * @param   {String} token2 - Access token
 * @returns {Boolean} Return true if successful match, else false
 */
const safeCompare = function (token1, token2) {
  const token1Length = Buffer.byteLength(token1, 'utf8');
  const token2Length = Buffer.byteLength(token2, 'utf8');
  const bufferLength = (token1Length > token2Length) ? token1Length : token2Length;
  const token1Buffer = Buffer.alloc(bufferLength);
  const token2Buffer = Buffer.alloc(bufferLength);
  token1Buffer.write(token1, 'utf8');
  token2Buffer.write(token2, 'utf8');
  return crypto.timingSafeEqual(token1Buffer, token2Buffer);
};

/**
 * Lookup access token to return cached token meta-data
 * @param {Object} chain - chain object passes access token and metadata
 * @param {Object} chain.options argument to requireAccessToken(options) authorization
 * @param {string|string[]} chain.options.scope - Token scope restrictions
 * @param {string} chain.accessToken - Oauth 2.0 JWT access token
 * @param {Object} chain.introspect - Decoded token metadata
 * @returns {Promise} Resolved with chain object
 */
const _findCachedToken = (chain) => {
  if ((!(chain == null)) &&
    (Object.hasOwn(chain, 'accessToken')) && (!(chain.accessToken == null))) {
    // If not cache disabled (seconds = 0), lookup the token
    if (tokenCacheSeconds > 0) {
      const found = tokenCache.find((storedToken) => {
        return (
          // storedToken is found
          (safeCompare(storedToken.token, chain.accessToken)) &&
          // Token is "active" state from auth server
          (storedToken.introspect.active) &&
          // Access-token not expired (unix time in seconds)
          (storedToken.introspect.exp > Math.floor(Date.now() / 1000)) &&
          // Cache entry not expired (Time as javascript Date object)
          (storedToken.cacheExpires > new Date())
        );
      });
      if (found) {
        // console.log('Access token found in tokenCache');
        // found, return authorization metadata
        chain.introspect = found.introspect;
        chain.introspectWasCached = true;
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
 * If a trusted token exists in the cache, the token is trusted implicitly
 * without sending the token to the authorization server.
 * @param {Object} chain - chain object passes access token and metadata
 * @param {Object} chain.options argument to requireAccessToken(options) authorization
 * @param {string|string[]} chain.options.scope - Token scope restrictions
 * @param {string} chain.accessToken - Oauth 2.0 JWT access token
 * @param {Object} chain.introspect - Decoded token metadata
 * @throws Throws error on fetch network request failure
 * @returns {Promise} resolving to chain object.
 */
const _validateToken = (chain) => {
  // console.log(JSON.stringify(chain, null, 2));
  // Unexpired tokens in cache are assumed to be valid.
  // Check for cached token, if valid token from cache, return it.
  if ((!(chain == null)) &&
    (Object.hasOwn(chain, 'accessToken')) &&
    (!(chain.accessToken == null)) && (chain.accessToken.length > 0) &&
    (Object.hasOwn(chain, 'introspectWasCached')) && (chain.introspectWasCached === true) &&
    (Object.hasOwn(chain, 'introspect')) &&
    (Object.hasOwn(chain.introspect, 'active')) && (chain.introspect.active === true)) {
    // console.log('validate cached, skipping fetch');
    // Cached tokens that are not expired are trusted implicitly
    return Promise.resolve(chain);
  } else {
    return new Promise((resolve, reject) => {
      // Else, not cached, send access token to authorization server for validation
      //
      // Network request supervisory timer
      const fetchController = new AbortController();
      // Authorization server introspect route
      const fetchURL = authURL + '/oauth/introspect';
      const clientAuth = Buffer.from(clientId + ':' + clientSecret).toString('base64');
      const body = {
        access_token: chain.accessToken
      };
      const fetchOptions = {
        method: 'POST',
        redirect: 'error',
        cache: 'no-store',
        signal: fetchController.signal,
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          Authorization: 'Basic ' + clientAuth
        },
        body: JSON.stringify(body)
      };
      const fetchTimerId = setTimeout(() => fetchController.abort(), 5000);
      fetch(fetchURL, fetchOptions)
        .then((response) => {
          if (response.status === 200) {
            return response.json();
          } else {
            // Retrieve error message from remote web server and pass to error handler
            return response.text()
              .then((remoteErrorText) => {
                const err = new Error('HTTP status error');
                err.status = response.status;
                err.statusText = response.statusText;
                err.remoteErrorText = remoteErrorText;
                if (response.headers.get('WWW-Authenticate')) {
                  err.oauthHeaderText = response.headers.get('WWW-Authenticate');
                }
                throw err;
              });
          }
        })
        .then((responseJson) => {
          // console.log('responseJson ' + JSON.stringify(responseJson, null, 2));
          if (fetchTimerId) clearTimeout(fetchTimerId);
          // Save token meta-data. It's contents validated in the next function call.
          chain.introspect = responseJson;
          resolve(chain);
        })
        .catch((err) => {
          if (fetchTimerId) clearTimeout(fetchTimerId);
          // Build generic error message to catch network errors
          let message = ('Fetch error, ' + fetchOptions.method + ' ' + fetchURL + ', ' +
            (err.message || err.toString() || 'HTTP Error'));
          if (err.status) {
            // Case of HTTP status error, build descriptive error message
            message = ('HTTP status error, ') + err.status.toString() + ' ' +
              err.statusText + ', ' + fetchOptions.method + ' ' + fetchURL;
          }
          if (err.remoteErrorText) {
            message += ', ' + err.remoteErrorText;
          }
          if (err.oauthHeaderText) {
            message += ', ' + err.oauthHeaderText;
          }
          const error = new Error(message);
          error.status = 401;
          reject(error);
        });
    }); // new Promise()
  }
};

/**
 * Confirm token is active=true, therefore valid
 * @param {Object} chain - chain object passes access token and metadata
 * @param {Object} chain.options argument to requireAccessToken(options) authorization
 * @param {string|string[]} chain.options.scope - Token scope restrictions
 * @param {string} chain.accessToken - Oauth 2.0 JWT access token
 * @param {Object} chain.introspect - Decoded token metadata
 * @returns {Promise} Resolved with chain object, or reject with error
 */
const _checkTokenActive = (chain) => {
  if ((!(chain == null)) &&
    (Object.hasOwn(chain, 'accessToken')) && (!(chain.accessToken == null)) &&
    (Object.hasOwn(chain, 'introspect')) && (!(chain.introspect == null)) &&
    (Object.hasOwn(chain.introspect, 'active')) &&
    (chain.introspect.active === true) &&
    (Object.hasOwn(chain.introspect, 'client'))) {
    // console.log('checkTokenActive successful');
    return Promise.resolve(chain);
  } else {
    const err = new Error('Error, Token not active.');
    err.status = 401;
    return Promise.reject(err);
  }
};

/**
 * Cache token meta-data to service future requests
 * @param {Object} chain - chain object passes access token and metadata
 * @param {Object} chain.options argument to requireAccessToken(options) authorization
 * @param {string|string[]} chain.options.scope - Token scope restrictions
 * @param {string} chain.accessToken - Oauth 2.0 JWT access token
 * @param {Object} chain.introspect - Decoded token metadata
 * @returns {Promise} Resolved with chain object
 */
const _saveTokenToCache = (chain) => {
  // If cache enabled (second != 0), and token not previously cached.
  if (tokenCacheSeconds > 0) {
    if ((!(chain == null)) &&
      (Object.hasOwn(chain, 'accessToken')) && (!(chain.accessToken == null)) &&
      (Object.hasOwn(chain, 'introspect')) && (!(chain.introspect == null)) &&
      ((!Object.hasOwn(chain, 'introspectWasCached')))) {
      // console.log('saving token to tokenCache');
      tokenCache.push({
        token: chain.accessToken,
        introspect: chain.introspect,
        // Time as javascript Date object
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
 * Purpose:
 * During initial authorization check by requireAccessToken()
 * the token's scope is saved to the req object is to enable
 * middleware functions requireScopeForApiRoute() and matchScope()
 * to evaluate route specific scopes, to occur later in the request evaluation.
 * example:
 *   req.locals {
 *     tokenScope: [
 *       api.write
 *     ]
 *   }
 * @param {Object} req - Node request object
 * @param {Object} chain - chain object passes access token and metadata
 * @param {Object} chain.options argument to requireAccessToken(options) authorization
 * @param {string|string[]} chain.options.scope - Token scope restrictions
 * @param {string} chain.accessToken - Oauth 2.0 JWT access token
 * @param {Object} chain.introspect - Decoded token metadata
 * @returns {Promise} Resolved with chain object
 */
const _addTokenScopeToReqObject = (req, chain) => {
  if (!Object.hasOwn(req, 'locals')) req.locals = Object.create(null);
  if ((!(chain == null)) &&
    (Object.hasOwn(chain, 'introspect')) && (!(chain.introspect == null)) &&
    (Object.hasOwn(chain.introspect, 'scope'))) {
    req.locals.tokenScope = chain.introspect.scope || [];
  }
  return Promise.resolve(chain);
};

//
/**
 * Add user id and user number to node request object
 * Purpose:
 * 1) Optional custom backend code to restrict route access by user ID (read only own data)
 * 2) Optional custom backend code to perform database queries specific to an authorized user.
 * user.id:     type uuid.v4 (SQL, unique, required, primary index key)
 * user.number: type integer > 0 (alternate integer user id is available)
 * example:
 *   req.locals {
 *     user: {
 *       number: 1,
 *       id: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
 *     },
 *     userid: 1
 *   }
 * @param {Object} req - Node request object
 * @param {Object} chain - chain object passes access token and metadata
 * @param {Object} chain.options
 * @param {string|string[]} chain.options.scope - Token scope restrictions
 * @param {string} chain.accessToken - Oauth 2.0 JWT access token
 * @param {Object} chain.introspect - Decoded token metadata
 * @returns {Promise} Resolved with chain object
 */
const _addUserIdToReqObject = (req, chain) => {
  if (!Object.hasOwn(req, 'locals')) req.locals = Object.create(null);
  if ((!(chain == null)) &&
  (Object.hasOwn(chain, 'introspect')) && (!(chain.introspect == null)) &&
  (Object.hasOwn(chain.introspect, 'user'))) {
    if ((Object.hasOwn(chain.introspect.user, 'number')) &&
    (!(chain.introspect.user.number == null)) &&
    (chain.introspect.user.number > 0)) {
      if (!Object.hasOwn(req.locals, 'user')) req.locals.user = Object.create(null);
      req.locals.user.number = parseInt(chain.introspect.user.number);
      // Legacy property, in future req.locals.userid may be dropped
      // Please use req.locals.user.number
      req.locals.userid = parseInt(chain.introspect.user.number);
    }
    if ((Object.hasOwn(chain.introspect.user, 'id')) &&
      (!(chain.introspect.user.id == null)) &&
      (chain.introspect.user.id.length > 0)) {
      if (!Object.hasOwn(req.locals, 'user')) req.locals.user = Object.create(null);
      req.locals.user.id = chain.introspect.user.id;
    }
  }
  return Promise.resolve(chain);
};

/**
 * Optional: Restrict access based on scope or array of scopes
 * @param {Object} req - Node request object
 * @param {string[]}} req.locals.scope is array of strings extracted from access token
 * @param {Object} chain - chain object passes access token and metadata
 * @param {Object} chain.options
 * @param {string|string[]} chain.options.scope - From requireAccessToken({ scope: 'api.write' })
 * @param {string} chain.accessToken - Oauth 2.0 JWT access token
 * @param {Object} chain.introspect - Decoded token metadata
 * @returns {Promise} Resolved with chain object
 */
const _restrictByScope = (req, chain) => {
  if ((Object.hasOwn(chain, 'options')) && (!(chain.options == null)) &&
    (Object.hasOwn(chain.options, 'scope')) &&
    // may be non-empty array or non-empty string
    (chain.options.scope.length > 0)) {
    let scopeFound = false;
    if ((Object.hasOwn(req, 'locals')) &&
      (Object.hasOwn(req.locals, 'tokenScope'))) {
      // scope requirements from middleware argument requireAccessToken({ scope: 'api.write' })
      let chainScope = chain.options.scope;
      // decoded token scopes
      let reqScope = req.locals.tokenScope;
      if (typeof chainScope === 'string') chainScope = [chainScope];
      if (typeof reqScope === 'string') reqScope = [reqScope];
      if ((chainScope.length > 0) && (reqScope.length > 0)) {
        chainScope.forEach((scopeString) => {
          if (reqScope.indexOf(scopeString) >= 0) scopeFound = true;
        });
      }
    }
    if (scopeFound) {
      return Promise.resolve(chain);
    } else {
      const err = new Error('Forbidden, token has insufficient scope');
      err.status = 403;
      return Promise.reject(err);
    }
  } else {
    // Case of no scope restrictions in middleware requireAccessToken(options)
    // No options, or options not contain scope, Therefore no restriction, accept all.
    return Promise.resolve(chain);
  }
};

/**
 * Inserting this optional debug function into the promise chain
 * can be used to show progression of data added to the chain object.
 * @Example
 *  _initChainObject(options)
 *    .then((chain) => _extractTokenFromHeader(req, chain))
 *    .then((chain) => _debugShowChain(chain))  // <--------------------
 *    .then((chain) => _findCachedToken(chain))
 * @param   {Object} chain (Optional) - chain object used to pass data between multiple promises.
 * @returns {Promise} resolves to chain object containing new access token, or rejects error
*/
// eslint-disable-next-line no-unused-vars
const _debugShowChain = (req, chain) => {
  console.log('chain', JSON.stringify(chain, null, 2));
  console.log('req.locals', JSON.stringify(req.locals, null, 2));
  return Promise.resolve(chain);
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
exports.requireAccessToken = (options) => {
  return (req, res, next) => {
    //
    // Chain of asynchronous promises
    //
    _initChainObject(options)
      .then((chain) => _extractTokenFromHeader(req, chain))
      .then((chain) => _findCachedToken(chain))
      .then((chain) => _validateToken(chain))
      .then((chain) => _checkTokenActive(chain))
      .then((chain) => _saveTokenToCache(chain))
      .then((chain) => _addTokenScopeToReqObject(req, chain))
      .then((chain) => _addUserIdToReqObject(req, chain))
      .then((chain) => _restrictByScope(req, chain))
      // .then((chain) => _debugShowChain(req, chain))
      .then((chain) => { return next(); })
      .catch((err) => {
        let message = err.message || err.toString() || 'Token authentication error';
        console.log('Token auth: ' + message);
        // limit to 1 line
        message = message.split('\n')[0];
        // Two choices, 401 or 403
        let status = 401;
        if ((err.status) && (err.status === 403)) status = 403;
        if ((err.status) && (err.status === 500)) status = 500;
        return res.status(status).send(message);
      });
  };
};

/**
 * Middleware to enforce route specific token scope restrictions
 * @param   {string|string[]} requiredScope - Scope values that will be accepted
 * Scope value comes from middleware requireScopeForApiRoute(['api.write']).
 * @example
 * // Require scope for route (requireAccessToken() called previously)
 * app.get('/v1, requireAccessToken(), ... )
 * // requireScopeForApiRoute uses tokens scope extracted in requireAccessToken()
 * router.get('/v1/someRoute',
 *   requireScopeForApiRoute(['api.read', 'api.write', 'api.admin']),
 *   validations.list, controller.list);
 * @throws Throws error on missing argument
 **/
exports.requireScopeForApiRoute = (requiredScope) => {
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
    if ((Object.hasOwn(req, 'locals')) &&
      (Object.hasOwn(req.locals, 'tokenScope')) &&
      (Array.isArray(req.locals.tokenScope))) {
      requiredScope.forEach((scopeString) => {
        if (req.locals.tokenScope.indexOf(scopeString) >= 0) scopeFound = true;
      });
      if (scopeFound) {
        return next();
      } else {
        const message = 'Token scope: Forbidden, Access token insufficient scope';
        console.log(message);
        return res.status(403).send(message);
      }
    } else {
      const err = new Error('Error, Tokens scope not found in request object');
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
exports.matchScope = (req, requiredScope) => {
  if ((requiredScope == null) ||
    ((typeof requiredScope !== 'string') &&
    (!Array.isArray(requiredScope)))) {
    throw new Error('matchScope requires string or array');
  }
  if (typeof requiredScope === 'string') {
    requiredScope = [requiredScope];
  }
  let scopeFound = false;
  if ((Object.hasOwn(req, 'locals')) &&
    (Object.hasOwn(req.locals, 'tokenScope')) &&
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
