'use strict'

const testMiddleware = (req, res, next) => {
  next();
};

module.exports = {
  testMiddleware
}
