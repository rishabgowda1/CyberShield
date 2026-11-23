'use strict';
/** Error whose message is safe to show to the end user. */
class AppError extends Error {
  constructor(message, code = 'ERROR', status = 400) {
    super(message);
    this.name = 'AppError';
    this.code = code;
    this.status = status;
    this.expose = true;
  }
}
module.exports = { AppError };
