package ndn

import (
	"encoding/binary"
	"math/rand"
	"strconv"

	"github.com/eric135/go-ndn/an"
	"github.com/eric135/go-ndn/tlv"
)

func lpIsCritical(typ uint32) bool {
	return typ < 800 || typ > 959 && (typ&0x03) != 0
}

// LpL3 contains layer 3 fields in NDNLPv2 header.
type LpL3 struct {
	PitToken        []byte
	NextHopFaceID   int
	IncomingFaceID  int
	CachePolicyType int // CachePolicy wrapper is implicit
	CongestionMark  int
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
		fields = append(fields, tlv.MakeElementNNI(an.TtLpCongestionMark, lph.CongestionMark))
	}

	return fields
}

func (lph *LpL3) inheritFrom(src LpL3) {
	lph.PitToken = src.PitToken
	lph.NextHopFaceID = src.NextHopFaceID
	lph.IncomingFaceID = src.IncomingFaceID
	lph.CachePolicyType = src.CachePolicyType
	lph.CongestionMark = src.CongestionMark
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

// LpFragment represents an NDNLPv2 fragmented frame.
type LpFragment struct {
	Sequence  uint64
	FragIndex int
	FragCount int
	header    []byte
	payload   []byte
}

func (frag LpFragment) String() string {
	return strconv.FormatUint(frag.Sequence, 16) + ":" + strconv.Itoa(frag.FragIndex) + ":" + strconv.Itoa(frag.FragCount)
}

// MarshalTlv encodes this fragment.
func (frag LpFragment) MarshalTlv() (typ uint32, value []byte, e error) {
	if frag.FragIndex < 0 || frag.FragIndex >= frag.FragCount {
		return 0, nil, ErrFragment
	}
	seqNum := make([]byte, 8)
	binary.BigEndian.PutUint64(seqNum, frag.Sequence)
	return tlv.EncodeTlv(an.TtLpPacket,
		tlv.MakeElement(an.TtLpSequence, seqNum),
		tlv.MakeElementNNI(an.TtLpFragIndex, frag.FragIndex),
		tlv.MakeElementNNI(an.TtLpFragCount, frag.FragCount),
		frag.header,
		tlv.MakeElement(an.TtLpFragment, frag.payload))
}

// LpFragmenter splits Packet into fragments.
type LpFragmenter struct {
	nextSeqNum uint64
	room       int
}

// NewLpFragmenter creates a LpFragmenter.
func NewLpFragmenter(mtu int) *LpFragmenter {
	var fragmenter LpFragmenter
	fragmenter.nextSeqNum = rand.Uint64()
	fragmenter.room = mtu - fragmentOverhead
	return &fragmenter
}

// Fragment fragments a packet.
func (fragmenter *LpFragmenter) Fragment(full *Packet) (frags []*Packet, e error) {
	header, payload, e := full.encodeL3()
	if e != nil {
		return nil, e
	}
	sizeofFirstFragment := fragmenter.room - len(header)
	if sizeofPayload := len(payload); sizeofFirstFragment > sizeofPayload { // no fragmentation necessary
		return []*Packet{full}, nil
	}

	if sizeofFirstFragment <= 0 { // MTU is too small to fit this packet
		return nil, ErrFragment
	}

	var first Packet
	first.Lp = full.Lp
	first.Fragment = &LpFragment{
		header:  header,
		payload: payload[:sizeofFirstFragment],
	}
	frags = append(frags, &first)

	for offset, nextOffset := sizeofFirstFragment, 0; offset < len(payload); offset = nextOffset {
		nextOffset = offset + fragmenter.room
		if nextOffset > len(payload) {
			nextOffset = len(payload)
		}

		var frag Packet
		frag.Fragment = &LpFragment{
			payload: payload[offset:nextOffset],
		}
		frags = append(frags, &frag)
	}

	for i, frag := range frags {
		frag.Fragment.Sequence = fragmenter.nextSeqNum
		fragmenter.nextSeqNum++
		frag.Fragment.FragIndex = i
		frag.Fragment.FragCount = len(frags)
	}
	return frags, nil
}

const fragmentOverhead = 0 +
	1 + 3 + // LpPacket TL
	1 + 1 + 8 + // LpSequence
	1 + 1 + 2 + // FragIndex
	1 + 1 + 2 + // FragCount
	1 + 3 + // LpPayload TL
	0
