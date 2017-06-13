'use strict';

const assert = require('assert');
const secp256k1 = require('secp256k1');
const HDKey = require('hdkey');
const utils = require('./utils');
const jsonrpc = require('jsonrpc-lite');
const { Transform } = require('stream');


/**
 * Implements the spartacus decorations to the node object
 */
class SpartacusPlugin {

  /**
   * Creates the plugin instance given a node and optional identity
   * @constructor
   * @param {KademliaNode} node
   * @param {buffer} [privateExtendedKey] - HD extended private key
   * @param {number} [derivationIndex] - Child key derivation index
   * @param {string} [derivationPath] - Child key derivation path
   */
  constructor(node, xpriv = utils.toHDKeyFromSeed().privateExtendedKey, i, p) {
    this.derivationIndex = i || 0;
    this.hdKeyPair = HDKey.fromExtendedKey(xpriv);

    if (p) {
      this.hdKeyPair = this.hdKeyPair.derive(p);
    }

    this.childKeys = this.derivationIndex === -1
                   ? this.hdKeyPair
                   : this.hdKeyPair.deriveChild(this.derivationIndex);

    this.publicExtendedKey = this.hdKeyPair.publicExtendedKey;
    this.privateExtendedKey = this.hdKeyPair.privateExtendedKey;
    this.publicKey = this.childKeys.publicKey;
    this.privateKey = this.childKeys.privateKey;
    this.identity = utils.toPublicKeyHash(this.publicKey);

    node.contact.xpub = this.publicExtendedKey;
    node.contact.index = this.derivationIndex;
    node.identity = node.router.identity = this.identity;

    node.rpc.serializer.append(new Transform({
      transform: this.serialize.bind(this),
      objectMode: true
    }));
    node.rpc.deserializer.prepend(new Transform({
      transform: this.deserialize.bind(this),
      objectMode: true
    }));
  }

  /**
   * Processes with JsonRpcSerializer then signs the result and appends an
   * additional payload containing signature+identity information
   * @param {object} data
   * @param {string} encoding
   * @param {function} callback
   */
  serialize(data, encoding, callback) {
    let [id, buffer, target] = data;
    let payload = jsonrpc.parse(buffer.toString('utf8')).map((obj) => {
      return obj.payload;
    });
    let { signature, recovery } = secp256k1.sign(
      utils._sha256(buffer),
      this.privateKey
    );
    let authenticate = jsonrpc.notification('AUTHENTICATE', [
      Buffer.concat([Buffer.from([recovery]), signature]).toString('base64'),
      this.publicKey.toString('hex'),
      [this.publicExtendedKey, this.derivationIndex]
    ]);

    payload.push(authenticate);
    callback(null, [
      id,
      Buffer.from(JSON.stringify(payload), 'utf8'),
      target
    ]);
  }

  /**
   * Parses and verifies the signature payload, then passes through to the
   * JsonRpcDeserializer if successful
   * @param {buffer} data
   * @param {string} encoding
   * @param {function} callback
   */
  deserialize(buffer, encoding, callback) {
    let payload = jsonrpc.parse(buffer.toString('utf8'))

    try {
      payload = payload.map((obj) => obj.payload);
    } catch (err) {
      return callback(new Error('Failed to parse received payload'));
    }

    let [rpc, identify, authenticate] = payload;
    let identity = Buffer.from(identify.params[0], 'hex');
    let [signature, publicKey, [xpub, index]] = authenticate.params;
    let signedPayload = utils._sha256(
      Buffer.from(JSON.stringify([rpc, identify]), 'utf8')
    );

    let publicKeyHash = utils.toPublicKeyHash(Buffer.from(publicKey, 'hex'));
    let isValidChildKey = utils.isDerivedFromExtendedPublicKey(
      publicKey,
      xpub,
      index
    );

    if (publicKeyHash.compare(identity) !== 0) {
      return callback(new Error('Identity does not match public key'));
    }

    if (!isValidChildKey) {
      return callback(new Error('Public key is not a valid child'));
    }

    try {
      assert.ok(secp256k1.verify(
        signedPayload,
        Buffer.from(signature, 'base64').slice(1),
        Buffer.from(publicKey, 'hex')
      ));
    } catch (err) {
      return callback(new Error('Message includes invalid signature'));
    }

    callback(null, buffer);
  }

}

module.exports = SpartacusPlugin;
