# Go-NDN: Named Data Networking Forwarder Library for Go

Go-NDN is a fork of the [NDNgo](https://github.com/usnistgov/ndn-dpdk/tree/master/ndn) library specialized for use with the [YaNFD](https://github.com/eric135/YaNFD) forwarder. This was done to implement missing features that are needed for this forwarder and reduce the size of the dependency.

## Features

### Packet Encoding and Decoding

* General purpose TLV codec (in [package tlv](tlv))
* Interests and Data packets: [v0.3](https://named-data.net/doc/NDN-packet-spec/0.3/) format only
  * TLV evolvability: yes
  * Signed Interest: basic support (**expansion planned**)
* [NDNLPv2](https://redmine.named-data.net/projects/nfd/wiki/NDNLPv2)
  * Fragmentation and reassembly: **planned**
  * Nacks: no
  * PIT tokens: yes
  * Congestion marks: yes
  * Link layer reliability: **planned**
  * Self-learning: **planned**
* Naming Convention: no

### Key Chain

* Encryption: no
* Signing algorithms
  * SHA256: yes
  * SHA256-RSA: yes (in [package rsakey](keychain/rsakey))
  * SHA256-ECDSA: yes (in [package eckey](keychain/eckey))
  * HMAC-SHA256: **planned**
  * [Null](https://redmine.named-data.net/projects/ndn-tlv/wiki/NullSignature): yes
* [NDN certificates](https://named-data.net/doc/ndn-cxx/0.7.0/specs/certificate-format.html): **planned**
* Key persistence: **planned**
* Trust schema: **planned**
