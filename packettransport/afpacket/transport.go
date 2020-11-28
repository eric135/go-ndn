// Package afpacket implements a transport that communicates over AF_PACKET sockets.
// This only works on Linux.
package afpacket

import (
	"encoding/binary"
	"fmt"
	"net"
	"reflect"

	"github.com/eric135/go-ndn/l3"
	"github.com/eric135/go-ndn/packettransport"
	af "github.com/google/gopacket/afpacket"
	"github.com/usnistgov/ndn-dpdk/core/macaddr"
	"golang.org/x/sys/unix"
)

// Config contains Transport configuration.
type Config struct {
	packettransport.Config
}

// Transport is an l3.Transport that communicates over AF_PACKET sockets.
type Transport interface {
	packettransport.Transport

	// Intf returns the underlying network interface.
	Intf() net.Interface
}

// New creates a Transport.
func New(ifname string, cfg Config) (Transport, error) {
	intf, e := net.InterfaceByName(ifname)
	if e != nil {
		return nil, fmt.Errorf("net.InterfaceByName(%s) %w", ifname, e)
	}
	if cfg.Local.Empty() {
		cfg.Local.HardwareAddr = intf.HardwareAddr
	}
	if cfg.Remote.Empty() {
		cfg.Remote.HardwareAddr = packettransport.MulticastAddressNDN
	}

	h, e := af.NewTPacket()
	if e != nil {
		return nil, fmt.Errorf("af.NewTPacket() %w", e)
	}

	tr := &transport{
		intf: *intf,
	}
	if e = tr.prepare(h, cfg.Locator); e != nil {
		return nil, e
	}

	tr.Transport, e = packettransport.New(h, cfg.Config)
	if e != nil {
		return nil, e
	}
	tr.Transport.OnStateChange(func(st l3.TransportState) {
		if st == l3.TransportClosed {
			h.Close()
		}
	})
	return tr, nil
}

type transport struct {
	packettransport.Transport
	h    *af.TPacket
	intf net.Interface
}

func (tr *transport) prepare(h *af.TPacket, loc packettransport.Locator) error {
	fd := int(reflect.ValueOf(h).Elem().FieldByName("fd").Int())
	ifindex := tr.intf.Index
	ethtype := make([]byte, 2)
	binary.BigEndian.PutUint16(ethtype, packettransport.EthernetTypeNDN)
	sockaddr := unix.SockaddrLinklayer{
		Protocol: binary.LittleEndian.Uint16(ethtype),
		Ifindex:  ifindex,
	}
	if e := unix.Bind(fd, &sockaddr); e != nil {
		return fmt.Errorf("bind(fd=%d, ifindex=%d) %w", fd, ifindex, e)
	}

	if macaddr.IsMulticast(loc.Remote.HardwareAddr) {
		mreq := unix.PacketMreq{
			Ifindex: int32(ifindex),
			Type:    unix.PACKET_MR_MULTICAST,
		}
		mreq.Alen = uint16(copy(mreq.Address[:], []byte(loc.Remote.HardwareAddr)))
		if e := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq); e != nil {
			return fmt.Errorf("setsockopt(fd=%d, ifindex=%d, PACKET_ADD_MEMBERSHIP=%s) %w", fd, ifindex, loc.Remote, e)
		}
	} else if !macaddr.Equal(loc.Local.HardwareAddr, tr.intf.HardwareAddr) {
		mreq := unix.PacketMreq{
			Ifindex: int32(ifindex),
			Type:    unix.PACKET_MR_PROMISC,
		}
		if e := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq); e != nil {
			return fmt.Errorf("setsockopt(fd=%d, ifindex=%d, PACKET_ADD_MEMBERSHIP=PROMISC) %w", fd, ifindex, e)
		}
	}

	return nil
}

func (tr *transport) Intf() net.Interface {
	return tr.intf
}

func (tr *transport) Close() error {
	tr.h.Close()
	return nil
}
