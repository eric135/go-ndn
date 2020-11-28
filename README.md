# Go-NDN: Named Data Networking Library for Go

Go-NDN is a fork of the [NDNgo](https://github.com/usnistgov/ndn-dpdk/tree/master/ndn) library specialized for use with the YaNFD forwarder. This was done to implement missing features that are needed for this forwarder and reduce the size of the dependency.

## Features

Packet encoding and decoding

* General purpose TLV codec (in [package tlv](tlv))
* Interest and Data: [v0.3](https://named-data.net/doc/NDN-packet-spec/0.3/) format only
  * TLV evolvability: yes
  * Signed Interest: basic support
* [NDNLPv2](https://redmine.named-data.net/projects/nfd/wiki/NDNLPv2)
  * Fragmentation and reassembly: no
  * Nack: yes
  * PIT token: yes
  * Congestion mark: yes
  * Link layer reliability: no
* Naming Convention: no

Transports

* Unix stream, UDP unicast, TCP (in [package sockettransport](sockettransport))
* Ethernet via [GoPacket library](https://github.com/google/gopacket) (in [package packettransport](packettransport))
* Shared memory with local NDN-DPDK forwarder via [memif](https://pkg.go.dev/github.com/FDio/vpp/extras/gomemif/memif?tab=doc) (in [package memiftransport](memiftransport))

KeyChain

* Encryption: no
* Signing algorithms
  * SHA256: yes
  * ECDSA: yes (in [package eckey](keychain/eckey))
  * RSA: yes (in [package rsakey](keychain/rsakey))
  * HMAC-SHA256: no
  * [Null](https://redmine.named-data.net/projects/ndn-tlv/wiki/NullSignature): yes
* [NDN certificates](https://named-data.net/doc/ndn-cxx/0.7.0/specs/certificate-format.html): no
* Key persistence: no
* Trust schema: no

Application layer services

* Endpoint: yes
* Segmented object producer and consumer: no
