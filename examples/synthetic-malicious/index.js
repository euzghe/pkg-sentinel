// Public API — looks benign on purpose. Real malware lives in ./scripts/setup.js
// (which npm runs automatically via postinstall).
'use strict';

module.exports = {
  version: function () {
    return '1.0.4';
  },
};
