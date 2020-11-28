package an

// ContentType assigned numbers.
const (
	ContentBlob      = 0x00
	ContentLink      = 0x01
	ContentKey       = 0x02
	ContentNack      = 0x03
	Manifest         = 0x04
	ContentPrefixAnn = 0x05
	KiteAck          = 0x06
	FLIC             = 0x400

	_ = "enumgen:ContentType"
)
