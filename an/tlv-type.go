package an

// TLV-TYPE assigned numbers.
const (
	TtInvalid = 0x00

	// Packet types
	TtInterest = 0x05
	TtData     = 0x06

	// Common fields
	TtName                            = 0x07
	TtGenericNameComponent            = 0x08
	TtImplicitSha256DigestComponent   = 0x01
	TtParametersSha256DigestComponent = 0x02

	// Interest packet
	TtCanBePrefix            = 0x21
	TtMustBeFresh            = 0x12
	TtForwardingHint         = 0x1E
	TtNonce                  = 0x0A
	TtInterestLifetime       = 0x0C
	TtHopLimit               = 0x22
	TtApplicationParameters  = 0x24
	TtInterestSignatureInfo  = 0x2C
	TtInterestSignatureValue = 0x2E

	// Data packet
	TtMetaInfo       = 0x14
	TtContent        = 0x15
	TtSignatureInfo  = 0x16
	TtSignatureValue = 0x17

	// Data/MetaInfo
	TtContentType     = 0x18
	TtFreshnessPeriod = 0x19
	TtFinalBlockID    = 0x1A

	// Signature
	TtSignatureType   = 0x1B
	TtKeyLocator      = 0x1C
	TtKeyDigest       = 0x1D
	TtSignatureNonce  = 0x26
	TtSignatureTime   = 0x28
	TtSignatureSeqNum = 0x2A

	// Link Object
	TtDelegation = 0x1F
	TtPreference = 0x1E

	// NDNLPv2 (https://redmine.named-data.net/projects/nfd/wiki/NDNLPv2)
	TtLpFragment           = 0x50
	TtLpSequence           = 0x51
	TtLpFragIndex          = 0x52
	TtLpFragCount          = 0x53
	TtLpHopCountNDNSim     = 0x54
	TtLpGeoTagNDNSim       = 0x55
	TtLpPitToken           = 0x62
	TtLpPacket             = 0x64
	TtLpNextHopFaceID      = 0x0330
	TtLpIncomingFaceID     = 0x0331
	TtLpCachePolicy        = 0x0334
	TtLpCachePolicyType    = 0x0335
	TtLpCongestionMark     = 0x0340
	TtLpAck                = 0x0344
	TtLpTxSequence         = 0x0348
	TtLpNonDiscovery       = 0x034C
	TtLpPrefixAnnouncement = 0x0350

	// Name Component Type Assignment (https://redmine.named-data.net/projects/ndn-tlv/wiki/NameComponentType)
	TtKeywordNameComponent     = 0x20
	TtSegmentNameComponent     = 0x21
	TtByteOffsetNameComponent  = 0x22
	TtVersionNameComponent     = 0x23
	TtTimestampNameComponent   = 0x24
	TtSequenceNumNameComponent = 0x25

	// NDN Certificate Format (https://named-data.net/doc/ndn-cxx/current/specs/certificate-format.html)
	TtValidityPeriod        = 0xFD
	TtNotBefore             = 0xFE
	TtNotAfter              = 0xFF
	TtAdditionalDescription = 0x0102
	TtDescriptionEntry      = 0x0200
	TtDescriptionKey        = 0x0201
	TtDescriptionValue      = 0x0202

	_ = "enumgen"
)
