# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
