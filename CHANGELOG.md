# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v2.0.0-dev (Draft) 2023-07-07

### BREAKING CHANGE (Node>=18)

BREAKING CHANGE (after v0.0.8) require Node 18 or greater. Incremented major version from 1 to 2

- Added engine.node>=18 in package.json

Upgrade to node 18 allows use of native NodeJS fetch() API for network requests.
Having dropped node-fetch, the collab-backend-token-auth now has zero NPM production dependencies.
The node-fetch repository used previously has moved on. The current 
version 3 of node-fetch is an ES Module that does not support CommonJS modules.

- Recoded the fetch() function used for the authorization server /oauth/introspect route.
- An abort controller was added to the fetch function with supervisory timer.
- In the case of a status not 200 error from the HTTP request to the authorization server, the fetch request will now request the text content of the error message from the authorization server for inclusion into the HTTP error response.

### Added (timing safe compare)

Added a timing safe compare to the function that searches for previously cached tokens 
in the token cache. This is to reduce risk of a timing attack trying to match 
a previously cached access token character by character.
Cached tokens that have not expired are trusted.

### Changed (Misc)

- Authorization header maximum length 4096. Exceeding length returns 401 error.
- In package.json set type: "commonjs"
- In code, now using Object.hasOwn to test if properties exist in an object, replacing `in` operator, or boolean check on key name.
- In various places, create new objects with Object.create(null), replacing object literal.
- To fix npm audit warning with eslint, erase and regenerate package-lock.json in v3 format, reinstall eslint, manually install semver@7.5.3.

### Added (req.locals.user)

In the case where user user tokens are submitted, the user id is added to the request object.
This allows optional custom backend code to restrict route access by user ID login.
This allows optional custom backend code to perform database queries specific to an authorized user login.
A new req.locals.user object was added to the request object, holding uuid.v4 "id" an integer user "number" values.
This does not apply to device or machine tokens obtained with client credentials grant, as they have no user information.

In the future req.locals.userid may be deprecated, Recommend using req.locals.user.number as replacement.

Before change:

```
req.locals {
  "userid": 1
}
```

After change:

```
req.locals {
  "user": {
    "number": 1,
    "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  },
  "userid": 1
}
```

## [v1.0.8](https://github.com/cotarr/collab-backend-token-auth/releases/tag/v1.0.8) - 2023-01-11

The npm security advisory for debug package has been updated to 
to incorporate backport debug@2.6.9 as safe. Manual edit of package-lock.json is 
no longer required.

- Deleted package-lock.json. Ran npm install to create a new package-lock.json.

## [v1.0.7](https://github.com/cotarr/collab-backend-token-auth/releases/tag/v1.0.7) - 2023-01-11

- Deleted package-lock.json, re-installed eslint and dependencies.
- package-lock.json - Manually upgrade eslint-plugin-import dependency to debug@4.3.4 to clear dependabot alert.

## [v1.0.6](https://github.com/cotarr/collab-backend-token-auth/releases/tag/v1.0.6) - 2022-11-15

### Changed

- package-lock.json - Bumped minimatach v3.0.4 to v3.1.2, npm audit fix to address github dependabot alert.

## [v1.0.5](https://github.com/cotarr/collab-backend-token-auth/releases/tag/v1.0.5) - 2022-03-31

### Changed

- package.json - Downgrade eslint to 7.32.0 to fix dependency errors. No code changes.

## [v1.0.4](https://github.com/cotarr/collab-backend-token-auth/releases/tag/v1.0.4) - 2022-03-30

### Changed

- npm audit fix - bump mimimist 1.2.5 to 1.2.6 to address github dependabot security advisory for prototype pollution.

## [v1.0.3](https://github.com/cotarr/collab-backend-token-auth/releases/tag/v1.0.3) - 2022-02-11

### Changed

- .eslintrc.js - Added .eslintrc.js to extending eslint config: standard
- Updated eslint to current version as dev dependency package.json
- src/index.js - Minor linting for syntax, no code changes
- .npmignore - Added .npmignore to repository

## [v1.0.2](https://github.com/cotarr/collab-backend-token-auth/releases/tag/v1.0.2) - 2022-01-22

### Changed

- Update node-fetch to v2.6.7 to a address github advisory

## [v1.0.1](https://github.com/cotarr/collab-backend-token-auth/releases/tag/v1.0.1) - 2022-01-06

### Changed

- index.js - For clarity, changed function names to remove legacy references to passport library.
- README.md - Update documentation

### Added:

- index.js - In function requireAccessToken(), added check that configuration variables were initialized by running authInit().

## [v1.0.0](https://github.com/cotarr/collab-backend-token-auth/releases/tag/v1.0.0) - 2022-01-03

Initial Commit
