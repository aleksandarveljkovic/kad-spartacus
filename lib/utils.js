/**
 * @module kad-spartacus/utils
 */

'use strict';

const { randomBytes, createHash } = require('crypto');
const hdkey = require('hdkey');


/**
 * @private
 */
exports._sha256 = function(input) {
  return createHash('sha256').update(input).digest();
};

/**
 * @private
 */
exports._rmd160 = function(input) {
  return createHash('rmd160').update(input).digest();
};

/**
 * Generates a private key or derives one from the supplied seed
 * @function
 * @param {buffer} [masterSeed]
 * @param {string} [derivationPath]
 * @returns {object}
 */
exports.toHDKeyFromSeed = function(masterSeed, derivationPath) {
  const hdKeyPair = hdkey.fromMasterSeed(masterSeed || randomBytes(64));

  /* istanbul ignore if */
  if (derivationPath) {
    return hdKeyPair.derive(derivationPath);
  }

  return hdKeyPair;
};

/**
 * Takes a plain secp256k1 private key and converts it to an HD key - note
 * that the chain code is zeroed out and thus provides no additional security.
 * @function
 * @param {buffer} privateKey
 * @returns {string}
 */
exports.toExtendedFromPrivateKey = function(priv) {
  const hdKeyPair = new hdkey();

  hdKeyPair.privateKey = priv;
  hdKeyPair.chainCode = Buffer(32).fill(0);

  return hdKeyPair.privateExtendedKey;
};

/**
 * Verifies the public key is derives from the index of the extended public
 * key. Special case: if index is -1, then matches the public key against the
 * extended public key with zeroed chain code.
 * @param {string} hexPublicKey
 * @param {string} extPublicKey
 * @param {number} derivationIndex
 */
exports.isDerivedFromExtendedPublicKey = function(pub, xpub, i) {
  const hdKeyPair = hdkey.fromExtendedKey(xpub);

  if (i === -1) {
    return hdKeyPair.publicKey.toString('hex') === pub;
  }

  return pub === hdKeyPair.deriveChild(i).publicKey.toString('hex');
};

/**
 * Takes a public key are returns the identity
 * @param {buffer} publicKey
 * @returns {buffer}
 */
exports.toPublicKeyHash = function(publicKey) {
  return exports._rmd160(exports._sha256(publicKey));
};
