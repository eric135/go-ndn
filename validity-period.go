package ndn

import (
	"github.com/eric135/go-ndn/an"
	"github.com/eric135/go-ndn/tlv"
)

// ValidityPeriod contains two timestamps indicating a temporal range of validity.
type ValidityPeriod struct {
	NotBefore []byte
	NotAfter  []byte
}

// MarshalTlv encodes this ValidityPeriod.
func (v ValidityPeriod) MarshalTlv() (typ uint32, value []byte, e error) {
	return tlv.EncodeTlv(an.TtValidityPeriod, tlv.MakeElementNNI(an.TtNotBefore, v.NotBefore), tlv.MakeElement(an.TtNotAfter, v.NotAfter))
}
