/**
 * @module kad-spartacus
 */

'use strict';

/**
 * Registers the Spartacus implementation as a Kad plugin
 * @param {KademliaNode} node
 */
let index = module.exports = function(privateKey) {
  return function(node) {
    return new module.exports.SpartacusPlugin(node, privateKey);
  };
};

/** {@link SpartacusPlugin} */
index.SpartacusPlugin = require('./lib/plugin-spartacus');
index.createPrivateKey = index.SpartacusPlugin.createPrivateKey;
