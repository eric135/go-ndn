// Package memiftransport implements a transport over a shared memory packet interface (memif).
package memiftransport

import (
	"fmt"

	"github.com/eric135/go-ndn/l3"
	"github.com/eric135/go-ndn/packettransport"
	"github.com/usnistgov/ndn-dpdk/core/macaddr"
)

// Transport is an l3.Transport that communicates via libmemif.
type Transport interface {
	l3.Transport

	Locator() Locator
}

// New creates a Transport.
// The memif operates in slave mode.
func New(loc Locator) (Transport, error) {
	if e := loc.Validate(); e != nil {
		return nil, fmt.Errorf("loc.Validate %w", e)
	}
	loc.ApplyDefaults()

	hdl, e := newHandle(loc, false)
	if e != nil {
		return nil, e
	}

	packetCfg := packettransport.Config{
		Locator: packettransport.Locator{
			Local:  macaddr.Flag{HardwareAddr: AddressApp},
			Remote: macaddr.Flag{HardwareAddr: AddressDPDK},
		},
		TransportQueueConfig: loc.TransportQueueConfig,
	}
	packetTr, e := packettransport.New(hdl, packetCfg)

	return &transport{
		Transport: packetTr,
		loc:       loc,
	}, nil
}

type transport struct {
	packettransport.Transport
	loc Locator
}

func (tr *transport) Locator() Locator {
	return tr.loc
}
