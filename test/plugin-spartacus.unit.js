'use strict';

const { expect } = require('chai');
const sinon = require('sinon');
const proxyquire = require('proxyquire');
const secp256k1 = require('secp256k1');
const SpartacusPlugin = require('../lib/plugin-spartacus');


describe('SpartacusPlugin', function() {

  describe('@static createPrivateKey', function() {

    it('should return a 32 byte key', function() {
      const privateKey = SpartacusPlugin.createPrivateKey();
      expect(Buffer.isBuffer(privateKey)).to.equal(true);
      expect(privateKey).to.have.lengthOf(32);
    });

  });

  describe('@static toPublicKey', function() {

    it('should return a 33 byte key', function() {
      const privateKey = SpartacusPlugin.createPrivateKey();
      const publicKey = SpartacusPlugin.toPublicKey(privateKey);
      expect(Buffer.isBuffer(publicKey)).to.equal(true);
      expect(publicKey).to.have.lengthOf(33);
    });

  });

  describe('@static toPublicKeyHash', function() {

    it('should return a 20 byte key', function() {
      const privateKey = SpartacusPlugin.createPrivateKey();
      const publicKey = SpartacusPlugin.toPublicKey(privateKey);
      const publicKeyHash = SpartacusPlugin.toPublicKeyHash(publicKey);
      expect(Buffer.isBuffer(publicKeyHash)).to.equal(true);
      expect(publicKeyHash).to.have.lengthOf(20);
    });

  });

  describe('@constructor', function() {

    it('should replace node identity and overload rpc methods', function() {
      let id = SpartacusPlugin.toPublicKeyHash('test');
      let node = {
        identity: id,
        rpc: { _opts: {} },
        router: {}
      };
      let plugin = new SpartacusPlugin(node);
      expect(node.identity).to.equal(plugin.identity);
      expect(node.router.identity).to.equal(plugin.identity);
      expect(typeof node.rpc._opts.serializer).to.equal('function');
      expect(typeof node.rpc._opts.deserializer).to.equal('function');
    });

  });

  describe('@method serialize', function() {

    it('should callback error if JsonRpcSerializer fails', function(done) {
      let Plugin = proxyquire('../lib/plugin-spartacus', {
        kad: {
          Messenger: {
            JsonRpcSerializer: sinon.stub().callsArgWith(
              1,
              new Error('Parse error')
            )
          }
        }
      });
      let node = { identity: null, rpc: { _opts: {} }, router: {} };
      let plugin = new Plugin(node);
      plugin.serialize([], (err) => {
        expect(err.message).to.equal('Parse error');
        done();
      });
    });

    it('should add an AUTHENTICATE message to the payload', function(done) {
      let node = { identity: null, rpc: { _opts: {} }, router: {} };
      let plugin = new SpartacusPlugin(node);
      plugin.serialize([
        { method: 'PING', params: [] },
        [
          plugin.identity.toString('hex'),
          { hostname: 'localhost', port: 8080 }
        ],
        [
          SpartacusPlugin.toPublicKeyHash('test').toString('hex'),
          { hostname: 'localhost', port: 8080}
        ]
      ], (err, [, buffer]) => {
        let result = JSON.parse(buffer.toString());
        expect(result).to.have.lengthOf(3);
        expect(result[1].params[0]).to.equal(plugin.identity.toString('hex'));
        expect(result[2].params).to.have.lengthOf(2);
        done();
      });
    });

  });

  describe('@method deserialize', function() {

    it('should callback error if id is not pubkeyhash', function(done) {
      let node = { identity: null, rpc: { _opts: {} }, router: {} };
      let plugin = new SpartacusPlugin(node);
      plugin.deserialize(Buffer.from(JSON.stringify([
        {
          jsonrpc: '2.0',
          id: 'test',
          method: 'PING',
          params: []
        },
        {
          jsonrpc: '2.0',
          method: 'IDENTIFY',
          params: [
            '0000ff',
            { hostname: 'localhost', port: 8080 }
          ]
        },
        {
          jsonrpc: '2.0',
          method: 'AUTHENTICATE',
          params: [
            plugin.publicKey.toString('hex'),
            '0000ff'
          ]
        }
      ])), (err) => {
        expect(err.message).to.equal('Identity does not match public key');
        done();
      });
    });

    it('should callback error if invalid signature', function(done) {
      let node = { identity: null, rpc: { _opts: {} }, router: {} };
      let plugin = new SpartacusPlugin(node);
      plugin.deserialize(Buffer.from(JSON.stringify([
        {
          jsonrpc: '2.0',
          id: 'test',
          method: 'PING',
          params: []
        },
        {
          jsonrpc: '2.0',
          method: 'IDENTIFY',
          params: [
            plugin.identity.toString('hex'),
            { hostname: 'localhost', port: 8080 }
          ]
        },
        {
          jsonrpc: '2.0',
          method: 'AUTHENTICATE',
          params: [
            '583b0eb005a94f22410d2da645b62dc7cdd9288f7fece1fd67fd6d90f4ce0284' +
              '48d3fd353969dde8e9e73ad69178efda22008a4e642f32845e89c59ec83a68' +
              '8f',
            plugin.publicKey.toString('hex')
          ]
        }
      ])), (err) => {
        expect(err.message).to.equal('Message includes invalid signature');
        done();
      });
    });

    it('should pass buffer to the JsonRpcDeserializer', function(done) {
      let node = { identity: null, rpc: { _opts: {} }, router: {} };
      let plugin = new SpartacusPlugin(node);
      let payload = [
        {
          jsonrpc: '2.0',
          id: 'test',
          method: 'PING',
          params: []
        },
        {
          jsonrpc: '2.0',
          method: 'IDENTIFY',
          params: [
            plugin.identity.toString('hex'),
            { hostname: 'localhost', port: 8080 }
          ]
        }
      ];
      let signature = secp256k1.sign(
        SpartacusPlugin._sha256(Buffer.from(JSON.stringify(payload))),
        plugin.privateKey
      ).signature;
      let auth = {
        jsonrpc: '2.0',
        method: 'AUTHENTICATE',
        params: [
          signature.toString('hex'),
          plugin.publicKey.toString('hex')
        ]
      };
      payload.push(auth);
      plugin.deserialize(Buffer.from(JSON.stringify(payload)), (err, data) => {
        expect(err).to.equal(null);
        expect(Array.isArray(data)).to.equal(true);
        expect(data).to.have.lengthOf(2);
        done();
      });
    });

  });

});