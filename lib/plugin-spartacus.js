'use strict';

const { randomBytes } = require('crypto');
const secp256k1 = require('secp256k1');
const kad = require('kad');


/**
 * Implements the spartacus decorations to the node object
 */
class SpartacusPlugin {

  /**
   * Generates a valid ECDSA private key
   * @static
   * @memberof SpartacusPlugin
   * @returns {buffer}
   */
  static createPrivateKey() {
    let privateKey = randomBytes(32);

    while (!secp256k1.privateKeyVerify(privateKey)) {
      privateKey = randomBytes(32);
    }

    return privateKey;
  }

  /**
   * Creates the plugin instance given a node and optional identity
   * @constructor
   * @param {KademliaNode} node
   * @param {buffer} [privateKey] - ECDSA key (auto generated if omitted)
   */
  constructor(node, privateKey = SpartacusPlugin.createPrivateKey()) {
    this.node = node;
    this.privateKey = privateKey;

    // TODO: Replace node.identity with pubkeyhash
    // TODO: Replace node.rpc._opts.deserializer & node.rpc._opts.serializer

  }

}

module.exports = SpartacusPlugin;
