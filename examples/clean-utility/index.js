'use strict';

function titleCase(input) {
  if (typeof input !== 'string') {
    throw new TypeError('expected a string');
  }
  return input
    .toLowerCase()
    .split(/\s+/)
    .map((w) => (w.length === 0 ? w : w[0].toUpperCase() + w.slice(1)))
    .join(' ');
}

module.exports = titleCase;
module.exports.default = titleCase;
