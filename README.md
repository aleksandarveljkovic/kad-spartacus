Kad Spartacus
=============

[![Build Status](https://img.shields.io/travis/kadtools/kad-spartacus.svg?style=flat-square)](https://travis-ci.org/kadtools/kad-spartacus)
[![Coverage Status](https://img.shields.io/coveralls/kadtools/kad-spartacus.svg?style=flat-square)](https://coveralls.io/r/kadtools/kad-spartacus)
[![NPM](https://img.shields.io/npm/v/kad-spartacus.svg?style=flat-square)](https://www.npmjs.com/package/kad-spartacus)

Spartacus attack mitigation extension for
[Kad](https://github.com/kadtools/kad).

Usage
-----

Install with NPM.

```bash
npm install kad kad-spartacus --save
```

Integrate with your Kad project.

```js
const kad = require('kad');
const spartacus = require('kad-spartacus');
const secret = spartacus.createPrivateKey();
const node = kad({ /* options */ });

node.plugin(spartacus(secret));
```

The plugin will replace the `identity` of your `KademliaNode` with the hash of 
your public ECDSA key and wrap the message (de)serializer to sign outgoing 
messages and verify incoming messages.

About
-----

A Sybil variation is the Spartacus attack, where an attacker joins the network
claiming to have the same identity as another member. As specified, Kademlia has
no defense. In particular, a long-lived node can always steal a short-lived
node's identity.

A well-known defense is to require nodes to get their assigned identity from a
central server which is responsible for making sure that the distribution of
identities are even. A weaker solution is the requirement that identities be 
derived from the node's network address or similar.

Kad Spartacus takes a different approach to these problems. By introducing
cryptographic identities using ECDSA, nodes are required to prove that they
own their identity by signing messages with their private EC key and including
their public key in the message. The identity is derived from the public key,
therefore any node's claimed identity can be verified by checking it against the
included public key and verifying the signature.

Since the each node's identity is the RIPEMD160 hash of the SHA256 hash of the
ECDSA public key, we can ensure that nodes are not capable of claiming a
identity that does not belong to them. This is almost identical to how a
bitcoin address is created. In fact, the identity can be converted into a
bitcoin address by simply adding the network prefix and checksum, then encoding
as base58.

License
-------

Kad Spartacus - Spartacus attack mitigation for Kad
Copyright (C) 2017 Gordon Hall

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see http://www.gnu.org/licenses/.


