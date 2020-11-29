package ndn_test

import (
	"testing"

	"github.com/eric135/go-ndn"
	"github.com/eric135/go-ndn/tlv"
)

func TestLpPacketEncode(t *testing.T) {
	assert, _ := makeAR(t)

	lpPacket := ndn.MakeLpPacket()
	var interest ndn.Interest
	interest.Name = ndn.ParseName("/A")
	lpPacket.LpFragment.Interest = &interest

	wire, err := tlv.Encode(lpPacket)
	assert.NoError(err)
	assert.Equal(bytesFromHex("640F 500D 050B 0703080141 0A04"), wire[:13])
}

func TestLpPacketDecode(t *testing.T) {
	assert, _ := makeAR(t)

	var pkt ndn.LpPacket
	assert.NoError(tlv.Decode(bytesFromHex("641F sequence=51088877665544332211 fragindex=520100 fragcount=530101 500D 050B 0703080141 0A0401020304"), &pkt))

	assert.True(pkt.Sequence.HasValue)
	assert.Equal(uint64(0x8877665544332211), pkt.Sequence.Val)
	assert.Equal(0, pkt.FragIndex)
	assert.Equal(1, pkt.FragCount)

	assert.NotNil(pkt.LpFragment.Interest)
	interest := pkt.LpFragment.Interest
	nameEqual(assert, "/A", interest)
}

func TestLpPacketDecodeBare(t *testing.T) {
	assert, _ := makeAR(t)

	var pkt ndn.LpPacket
	assert.NoError(tlv.Decode(bytesFromHex("050B 0703080141 0A0401020304"), &pkt))

	assert.NotNil(pkt.LpFragment.Interest)
	interest := pkt.LpFragment.Interest
	nameEqual(assert, "/A", interest)
}
