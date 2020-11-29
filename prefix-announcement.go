package ndn

import (
	"github.com/eric135/go-ndn/an"
	"github.com/eric135/go-ndn/tlv"
)

// PrefixAnnouncement holds the Content field of a prefix announcement object.
type PrefixAnnouncement struct {
	ExpirationPeriod int
	ValidityPeriod   ValidityPeriod
}

// MarshalTlv encodes this PrefixAnnouncment.
func (a PrefixAnnouncement) MarshalTlv() (typ uint32, value []byte, e error) {
	validityType, validityValue, _ := a.ValidityPeriod.MarshalTlv()
	return tlv.EncodeTlv(an.TtContent, tlv.MakeElementNNI(an.MgmtExpirationPeriod, a.ExpirationPeriod), tlv.MakeElement(validityType, validityValue))
}
