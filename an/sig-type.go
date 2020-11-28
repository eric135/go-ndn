package an

import "strconv"

// SigType assigned numbers.
const (
	SignatureSha256          = 0x00
	SignatureSha256WithRsa   = 0x01
	SignatureSha256WithEcdsa = 0x03
	SignatureHmacWithSha256  = 0x04
	SignatureNull            = 0xC8

	_ = "enumgen:SigType"
)

// SigTypeString converts SigType to string.
func SigTypeString(sigType uint32) string {
	switch sigType {
	case SignatureSha256:
		return "SHA256"
	case SignatureSha256WithRsa:
		return "SHA256-RSA"
	case SignatureSha256WithEcdsa:
		return "SHA256-ECDSA"
	case SignatureHmacWithSha256:
		return "HMAC-SHA256"
	case SignatureNull:
		return "null"
	}
	return strconv.Itoa(int(sigType))
}
