'use strict';

const { expect } = require('chai');
const kad = require('kad');
const network = require('kad/test/fixtures/node-generator');
const spartacus = require('..');
const { randomBytes } = require('crypto');


describe('Kad Spartacus E2E (w/ UDPTransport)', function() {

  let [node1, node2] = network(2, kad.UDPTransport);

  before(function(done) {
    [node1, node2].forEach((node, i) => {
      if (i === 0) {
        node.plugin(spartacus(/* autogenerate */));
      } else {
        node.plugin(spartacus(spartacus.utils.toExtendedFromPrivateKey(
          randomBytes(32)
        ), -1));
      }
      node.listen(node.contact.port);
    });
    setTimeout(done, 1000);
  });

  it('should sign and verify messages', function(done) {
    node1.ping([node2.identity.toString('hex'), node2.contact], (err) => {
      expect(err).to.equal(null);
      done();
    });
  });

});
