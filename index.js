/**
 * @module kad-spartacus
 */

'use strict';

/**
 * Registers the Spartacus implementation as a Kad plugin
 * @param {string} xpriv - Extended private key
 * @param {number} index - Child derivation index
 */
let index = module.exports = function(xpriv, index) {
  return function(node) {
    return new module.exports.SpartacusPlugin(node, xpriv, index);
  };
};

/** {@link SpartacusPlugin} */
index.SpartacusPlugin = require('./lib/plugin-spartacus');

/** {@link module:kad-spartacus/utils} */
index.utils = require('./lib/utils');
