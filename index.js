/**
 * @module kad-spartacus
 */

'use strict';

/**
 * Registers the Spartacus implementation as a Kad plugin
 * @param {string} xpriv - Extended private key
 * @param {number} index - Child derivation index
 * @param {string} path - Child derivation path
 */
let index = module.exports = function(xpriv, index, path) {
  return function(node) {
    return new module.exports.SpartacusPlugin(node, xpriv, index, path);
  };
};

/** {@link SpartacusPlugin} */
index.SpartacusPlugin = require('./lib/plugin-spartacus');

/** {@link module:kad-spartacus/utils} */
index.utils = require('./lib/utils');
