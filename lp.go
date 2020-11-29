package ndn

import (
	"encoding/binary"
	"strconv"

	"github.com/eric135/go-ndn/an"
	"github.com/eric135/go-ndn/tlv"
	"github.com/eric135/go-ndn/util"
)

func lpIsCritical(typ uint32) bool {
	return typ < 800 || typ > 959 && (typ&0x03) != 0
}

// LpL3 contains layer 3 fields in NDNLPv2 header.
type LpL3 struct {
	PitToken        []byte
	NextHopFaceID   uint64
	IncomingFaceID  uint64
	CachePolicyType uint64 // CachePolicy wrapper is implicit
	CongestionMark  uint64
}

// Empty returns true if LpL3 has zero fields.
func (lph LpL3) Empty() bool {
	return len(lph.PitToken) == 0 && lph.NextHopFaceID == 0 && lph.IncomingFaceID == 0 && lph.CachePolicyType == 0 && lph.CongestionMark == 0
}

func (lph LpL3) encode() (fields []interface{}) {
	if len(lph.PitToken) > 0 {
		fields = append(fields, tlv.MakeElement(an.TtLpPitToken, lph.PitToken))
	}

	if lph.NextHopFaceID != 0 {
		fields = append(fields, tlv.MakeElementNNI(an.TtLpNextHopFaceID, lph.NextHopFaceID))
	}

	if lph.IncomingFaceID != 0 {
		fields = append(fields, tlv.MakeElementNNI(an.TtLpIncomingFaceID, lph.IncomingFaceID))
	}

	if lph.CachePolicyType != 0 {
		_, encodedCachePolicyType, _ := tlv.EncodeTlv(an.TtLpCachePolicyType, lph.CachePolicyType)
		fields = append(fields, tlv.MakeElement(an.TtLpCachePolicy, encodedCachePolicyType))
	}

	if lph.CongestionMark != 0 {
		fields = append(fields, tlv.MakeElementNNI(an.TtLpCongestionMark, 1))
	}

	return fields
}

func (lph LpL3) inheritFrom(src LpL3) {
	lph.PitToken = src.PitToken
	lph.NextHopFaceID = src.NextHopFaceID
	lph.IncomingFaceID = src.IncomingFaceID
	lph.CachePolicyType = src.CachePolicyType
	lph.CongestionMark = src.CongestionMark
}

// SelfLearningHeaders represents frame headers for self-learning.
type SelfLearningHeaders struct {
	NonDiscovery       bool
	PrefixAnnouncement Data
}

// Empty returns true if SelfLearningHeaders has zero fields.
func (slh SelfLearningHeaders) Empty() bool {
	return slh.NonDiscovery == false && len(slh.PrefixAnnouncement.Name) == 0
}

// Encode encodes the self-learning headers
func (slh SelfLearningHeaders) Encode() (fields []interface{}, err error) {
	if slh.NonDiscovery == true {
		fields = append(fields, tlv.MakeElement(an.TtLpNonDiscovery, []byte{}))
	}

	if len(slh.PrefixAnnouncement.Name) != 0 {
		announcementType, announcementValue, err := slh.PrefixAnnouncement.MarshalTlv()
		if err != nil {
			return nil, err
		}
		fields = append(fields, tlv.MakeElement(announcementType, announcementValue))
	}

	return fields, nil
}

// PitTokenFromUint creates a PIT token from uint64, interpreted as big endian.
func PitTokenFromUint(n uint64) []byte {
	token := make([]byte, 8)
	binary.BigEndian.PutUint64(token, n)
	return token
}

// PitTokenToUint reads a 8-octet PIT token as uint64, interpreted as big endian.
// Returns 0 if the input token is not 8 octets.
func PitTokenToUint(token []byte) uint64 {
	if len(token) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(token)
}

// LpPacket represents an NDNLPv2 frame.
type LpPacket struct {
	Sequence            util.OptionalUint64
	FragIndex           int
	FragCount           int
	Acks                []uint64
	TxSequence          util.OptionalUint64
	SelfLearningHeaders SelfLearningHeaders
	LpFragment          *Packet
}

// MakeLpPacket constructs an empty LpPacket.
func MakeLpPacket() LpPacket {
	return LpPacket{
		FragIndex:  -1,
		FragCount:  -1,
		LpFragment: &Packet{}}
}

func (lp LpPacket) String() string {
	retVal := ""
	hasPrevValue := false
	if lp.Sequence.HasValue {
		retVal += strconv.FormatUint(lp.Sequence.Val, 16)
		hasPrevValue = true
	}
	if lp.FragIndex >= 0 {
		if hasPrevValue {
			retVal += ":"
		}
		retVal += strconv.Itoa(lp.FragIndex)
		hasPrevValue = true
	}
	if lp.FragCount >= 0 {
		if hasPrevValue {
			retVal += ":"
		}
		retVal += strconv.Itoa(lp.FragCount)
	}
	return retVal
}

// MarshalTlv encodes this frame.
func (lp LpPacket) MarshalTlv() (typ uint32, value []byte, e error) {
	// Validate before encoding
	if (lp.FragIndex != -1 || lp.FragCount != -1) && (lp.FragIndex < 0 || lp.FragIndex >= lp.FragCount) {
		return 0, nil, ErrFragment
	}

	if (lp.FragIndex >= 0 || lp.FragCount >= 0) && !lp.Sequence.HasValue {
		// Fragmentation requires a sequence number
		return 0, nil, ErrFragment
	}

	if lp.TxSequence.HasValue != lp.Sequence.HasValue {
		// Reliability requires a Sequence number
		return 0, nil, ErrReliability
	}

	// Actually perform encoding
	fields := []interface{}{}

	if lp.Sequence.HasValue {
		seqNum := make([]byte, 8)
		binary.BigEndian.PutUint64(seqNum, lp.Sequence.Val)
		fields = append(fields, tlv.MakeElement(an.TtLpSequence, seqNum))
	}

	// Add L3 headers (if any)
	if lp.LpFragment.Interest != nil || lp.LpFragment.Data != nil {
		for _, v := range lp.LpFragment.Lp.encode() {
			fields = append(fields, v)
		}
	}

	if lp.FragIndex >= 0 {
		fields = append(fields, tlv.MakeElementNNI(an.TtLpFragIndex, lp.FragIndex))
	}

	if lp.FragCount > 0 {
		fields = append(fields, tlv.MakeElementNNI(an.TtLpFragIndex, lp.FragIndex))
	}

	for _, v := range lp.Acks {
		ack := make([]byte, 8)
		binary.BigEndian.PutUint64(ack, v)
		fields = append(fields, tlv.MakeElement(an.TtLpAck, ack))
	}

	if lp.TxSequence.HasValue {
		txSeqNum := make([]byte, 8)
		binary.BigEndian.PutUint64(txSeqNum, lp.TxSequence.Val)
		fields = append(fields, tlv.MakeElement(an.TtLpTxSequence, txSeqNum))
	}

	slHeaders, err := lp.SelfLearningHeaders.Encode()
	if err != nil {
		return 0, nil, err
	}
	for _, v := range slHeaders {
		fields = append(fields, v)
	}

	// Determine if not IDLE packet (has payload)
	if lp.LpFragment.Data != nil || lp.LpFragment.Interest != nil {
		encodedPayload, err := lp.LpFragment.encodeL3()
		if err != nil {
			return 0, nil, err
		}
		fields = append(fields, tlv.MakeElement(an.TtLpFragment, encodedPayload))
	}

	return tlv.EncodeTlv(an.TtLpPacket, fields)
}

// UnmarshalTlv decodes from wire format.
func (lp *LpPacket) UnmarshalTlv(typ uint32, value []byte) error {
	lp.Sequence.Unset()
	lp.FragIndex = -1
	lp.FragCount = -1
	lp.Acks = []uint64{}
	lp.TxSequence.Unset()
	lp.SelfLearningHeaders = SelfLearningHeaders{}
	lp.LpFragment = &Packet{}

	if typ == an.TtInterest || typ == an.TtData {
		// Decode bare Interest or Data
		return lp.LpFragment.decodeL3(typ, value)
	} else if typ != an.TtLpPacket {
		return ErrNotLpFrame
	}

	d := tlv.Decoder(value)
	for _, field := range d.Elements() {
		switch field.Type {
		case an.TtLpSequence:
			if len(field.Value) != 8 {
				return ErrSequenceSize
			}
			lp.Sequence.Set(binary.BigEndian.Uint64(field.Value))
		case an.TtLpFragIndex:
			if err := field.UnmarshalNNI(&lp.FragIndex); err != nil {
				return err
			}
		case an.TtLpFragCount:
			if err := field.UnmarshalNNI(&lp.FragCount); err != nil {
				return err
			}
		case an.TtLpPitToken:
			copy(lp.LpFragment.Lp.PitToken, field.Value)
		case an.TtLpNextHopFaceID:
			if err := field.UnmarshalNNI(&lp.LpFragment.Lp.NextHopFaceID); err != nil {
				return err
			}
		case an.TtLpIncomingFaceID:
			if err := field.UnmarshalNNI(&lp.LpFragment.Lp.IncomingFaceID); err != nil {
				return err
			}
		case an.TtLpCachePolicy:
			decoderCachePolicy := tlv.Decoder(field.Value)
			cachePolicyElement, err := decoderCachePolicy.Element()
			if err != nil {
				return err
			}
			if cachePolicyElement.Type != an.TtLpCachePolicyType {
				return ErrUnexpectedElem
			}
			if err := cachePolicyElement.UnmarshalNNI(&lp.LpFragment.Lp.CachePolicyType); err != nil {
				return err
			}
		case an.TtLpCongestionMark:
			if err := field.UnmarshalNNI(&lp.LpFragment.Lp.CongestionMark); err != nil {
				return err
			}
		case an.TtLpAck:
			if len(field.Value) != 8 {
				return ErrSequenceSize
			}
			lp.Acks = append(lp.Acks, binary.BigEndian.Uint64(field.Value))
		case an.TtLpTxSequence:
			if len(field.Value) != 8 {
				return ErrSequenceSize
			}
			lp.TxSequence.Set(binary.BigEndian.Uint64(field.Value))
		case an.TtLpFragment:
			d1 := tlv.Decoder(field.Value)
			field1, err := d1.Element()
			if err != nil {
				return err
			}
			err = lp.LpFragment.decodeL3(field1.Type, field1.Value)
			if err != nil {
				return err
			}
			if err := d1.ErrUnlessEOF(); err != nil {
				return err
			}
		}
	}
	return d.ErrUnlessEOF()
}
