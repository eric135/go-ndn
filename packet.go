// Package ndn implements Named Data Networking (NDN) packet semantics.
// This is the top-level package of NDNgo, a minimal NDN library in pure Go.
//
// This package contains the following important types:
//  Packet representation:
//  - Interest
//  - Data
//  - Packet
//
//  Security abstraction:
//  - Signer
//  - Verifier
package ndn

import (
	"encoding/hex"

	"github.com/eric135/go-ndn/an"
	"github.com/eric135/go-ndn/tlv"
)

// L3Packet represents any NDN layer 3 packet.
type L3Packet interface {
	ToPacket() *Packet
}

// Packet represents an NDN layer 3 packet with associated LpL3.
type Packet struct {
	Lp       LpL3
	l3type   uint32
	l3value  []byte
	l3digest []byte
	Fragment *LpFragment
	Interest *Interest
	Data     *Data
}

func (pkt *Packet) String() string {
	suffix := ""
	if len(pkt.Lp.PitToken) != 0 {
		suffix = " token=" + hex.EncodeToString(pkt.Lp.PitToken)
	}
	switch {
	case pkt.Fragment != nil:
		return "Frag " + pkt.Fragment.String() + suffix
	case pkt.Interest != nil:
		return "I " + pkt.Interest.String() + suffix
	case pkt.Data != nil:
		return "D " + pkt.Data.String() + suffix
	}
	return "(bad-NDN-packet)"
}

// ToPacket returns self.
func (pkt *Packet) ToPacket() *Packet {
	return pkt
}

// MarshalTlv encodes this packet.
func (pkt *Packet) MarshalTlv() (typ uint32, value []byte, e error) {
	if pkt.Fragment != nil {
		return pkt.Fragment.MarshalTlv()
	}

	header, payload, e := pkt.encodeL3()
	if e != nil {
		return 0, nil, e
	}

	if len(header) == 0 {
		return pkt.l3type, pkt.l3value, nil
	}
	return tlv.EncodeTlv(an.TtLpPacket, header, tlv.MakeElement(an.TtLpFragment, payload))
}

// UnmarshalTlv decodes from wire format.
func (pkt *Packet) UnmarshalTlv(typ uint32, value []byte) error {
	*pkt = Packet{}
	if typ != an.TtLpPacket {
		return pkt.decodeL3(typ, value)
	}

	d := tlv.Decoder(value)
	for _, field := range d.Elements() {
		switch field.Type {
		case an.TtLpPitToken:
			pkt.Lp.PitToken = field.Value
		case an.TtLpCongestionMark:
			if e := field.UnmarshalNNI(&pkt.Lp.CongestionMark); e != nil {
				return e
			}
		case an.TtLpFragment:
			d1 := tlv.Decoder(field.Value)
			field1, e := d1.Element()
			if e != nil {
				return e
			}
			e = pkt.decodeL3(field1.Type, field1.Value)
			if e != nil {
				return e
			}
			if e := d1.ErrUnlessEOF(); e != nil {
				return e
			}
		}
	}
	return d.ErrUnlessEOF()
}

func (pkt *Packet) encodeL3() (header, payload []byte, e error) {
	e = ErrFragment
	switch {
	case pkt.Interest != nil:
		pkt.l3type, pkt.l3value, e = pkt.Interest.MarshalTlv()
		pkt.l3digest = nil
	case pkt.Data != nil:
		pkt.l3type, pkt.l3value, e = pkt.Data.MarshalTlv()
		pkt.l3digest = nil
	}
	if e != nil {
		return nil, nil, e
	}

	header, _ = tlv.Encode(pkt.Lp.encode())
	payload, _ = tlv.Encode(tlv.MakeElement(pkt.l3type, pkt.l3value))
	return header, payload, nil
}

func (pkt *Packet) decodeL3(typ uint32, value []byte) error {
	switch typ {
	case an.TtInterest:
		var interest Interest
		e := interest.UnmarshalBinary(value)
		if e != nil {
			return e
		}
		interest.packet = pkt
		pkt.Interest = &interest
	case an.TtData:
		var data Data
		e := data.UnmarshalBinary(value)
		if e != nil {
			return e
		}
		data.packet = pkt
		pkt.Data = &data
	default:
		return ErrL3Type
	}

	pkt.l3type, pkt.l3value, pkt.l3digest = typ, value, nil
	return nil
}
