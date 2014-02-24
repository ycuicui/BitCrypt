BitCrypt
========

Description
-----------

BitCrypt is a specialized library for the Bitcoin cryptography. It is optimized for the Bitcoin EC Curve and provides a framework to manage keys and addresses.

Motivations
-----------

* Cryptographic library are not optimized for the Bitcoin Elliptic Curve.

* In the Bitcoin literature, the concepts of address and keys are not always clearly distinguished. In this project we define:
  * A private key as an element of the Elliptic curve field.
  * A public key as a point on the Elliptic curve. This key does not depend of how it could be represented externally (i.e. compressed or not).
  * An address as a hash of some public key representation. Thus, the same private key may result in two different address, one built from a compressed key and one with a non compressed key.

BitCrypt dependency
-------------------

BitCrypt has no external dependency. 

Packages
--------

### BitCrypt.curve

This package provides classes for the Bitcoin elliptic curve

* The ECCurve class defines all the elliptic curve parameters
* The ECFieldElement class represents elements of the field of Bitcoin EC points coordinates
* The ECPoint class represents points on the Elliptic curve.

All major operations on field elements are available, including square and cube roots.

Notice that some features are still "incubating", -i.e are not fully validated and not for production uses.

### BitCrypt.key

This package provides classes related to public and private keys as well as utilities to encode/decode keys.

* The ECKey class represents a Bitcoin key. Keys always defines a public value and optionally a private value. Keys must not be confused with the addresses.
* The EncodedPublicKey class is a wrapper around keys for use with Address generation. It specifically defines if a public key is compressed or not.
* The DumpedPrivateKey class is an utility to imports or exports private keys in the form used by the Bitcoin "dumpprivkey" command. 

### BitCrypt.address

This package provides the base Bitcoin Address class. An Address is defines by its hash. It could optionally be associated with a public and/or private key.

### BitCrypt.digest

This package provides hashing classes use in the Bitcoin protocol such as RIPEMD160 or SHA256.

### BitCrypt.signer

This package provides an utility class to:

* Sign a message
* Verify a signature
* Recover a public key from a signature

Licensing
---------

This work is released under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

Contributions
-------------

This work uses stolen code from the following projects

* [BitcoinJ](http://code.google.com/p/bitcoinj)
* [The Legion of the Bouncy Castle](http://www.bouncycastle.org/)
