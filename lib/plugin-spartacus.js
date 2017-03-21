'use strict';

const assert = require('assert');
const { createHash, randomBytes } = require('crypto');
const secp256k1 = require('secp256k1');
const { Messenger } = require('kad');
const jsonrpc = require('jsonrpc-lite');


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

    /* istanbul ignore next */
    while (!secp256k1.privateKeyVerify(privateKey)) {
      privateKey = randomBytes(32);
    }

    return privateKey;
  }

  /**
   * Takes a private key and returns the public key
   * @static
   * @memberof SpartacusPlugin
   * @param {buffer} privateKey
   * @returns {buffer}
   */
  static toPublicKey(privateKey) {
    return secp256k1.publicKeyCreate(privateKey);
  }

  /**
   * Takes a public key are returns the identity
   * @static
   * @memberof SpartacusPlugin
   * @param {buffer} publicKey
   * @returns {buffer}
   */
  static toPublicKeyHash(publicKey) {
    return SpartacusPlugin._rmd160(SpartacusPlugin._sha256(publicKey));
  }

  /**
   * @private
   */
  static _sha256(input) {
    return createHash('sha256').update(input).digest();
  }

  /**
   * @private
   */
  static _rmd160(input) {
    return createHash('rmd160').update(input).digest();
  }

  /**
   * Creates the plugin instance given a node and optional identity
   * @constructor
   * @param {KademliaNode} node
   * @param {buffer} [privateKey] - ECDSA key (auto generated if omitted)
   */
  constructor(node, privateKey = SpartacusPlugin.createPrivateKey()) {
    this.privateKey = privateKey;
    this.publicKey = SpartacusPlugin.toPublicKey(this.privateKey);
    this.identity = SpartacusPlugin.toPublicKeyHash(this.publicKey);

    node.identity = node.router.identity = this.identity;
    node.rpc._opts.serializer = this.serialize.bind(this);
    node.rpc._opts.deserializer = this.deserialize.bind(this);
  }

  /**
   * Processes with JsonRpcSerializer then signs the result and appends an
   * additional payload containing signature+identity information
   * @param {object} data
   * @param {function} callback
   */
  serialize(data, callback) {
    Messenger.JsonRpcSerializer(data, (err, data) => {
      if (err) {
        return callback(err);
      }

      let [id, buffer, target] = data;
      let payload = jsonrpc.parse(buffer.toString('utf8')).map((obj) => {
        return obj.payload;
      });
      let authenticate = jsonrpc.notification('AUTHENTICATE', [
        secp256k1.sign(
          SpartacusPlugin._sha256(buffer),
          this.privateKey
        ).signature.toString('hex'),
        this.publicKey.toString('hex')
      ]);

      payload.push(authenticate);
      callback(null, [
        id,
        Buffer.from(JSON.stringify(payload), 'utf8'),
        target
      ]);
    });
  }

  /**
   * Parses and verifies the signature payload, then passes through to the
   * JsonRpcDeserializer if successful
   * @param {buffer} data
   * @param {function} callback
   */
  deserialize(buffer, callback) {
    let payload = jsonrpc.parse(buffer.toString('utf8')).map(
      (obj) => obj.payload
    );
    let [rpc, identify, authenticate] = payload;
    let identity = Buffer.from(identify.params[0], 'hex');
    let [signature, publicKey] = authenticate.params.map(
      (hex) => Buffer.from(hex, 'hex')
    );
    let signedPayload = SpartacusPlugin._sha256(
      Buffer.from(JSON.stringify([rpc, identify]), 'utf8')
    );
    let publicKeyHash = SpartacusPlugin.toPublicKeyHash(publicKey);

    if (publicKeyHash.toString('hex') !== identity.toString('hex')) {
      return callback(new Error('Identity does not match public key'));
    }

    try {
      assert.ok(secp256k1.verify(signedPayload, signature, publicKey));
    } catch (err) {
      return callback(new Error('Message includes invalid signature'));
    }

    Messenger.JsonRpcDeserializer(buffer, callback);
  }

}

module.exports = SpartacusPlugin;
