package sockettransport

import (
	"github.com/eric135/go-ndn/tlv"
)

type streamRxLooper struct{}

func (streamRxLooper) RxLoop(tr *transport) error {
	buffer := make([]byte, tr.cfg.RxBufferLength)
	nAvail := 0
	for {
		nRead, e := tr.Conn().Read(buffer[nAvail:])
		if e != nil {
			return e
		}
		nAvail += nRead

		// parse and post packets
		d := tlv.Decoder(buffer[:nAvail])
		elements := d.Elements()
		if len(elements) == 0 {
			continue
		}

		for _, de := range elements {
			tr.p.Rx <- de.Wire
		}

		// copy remaining portion to a new buffer
		// can't reuse buffer because posted packets are still referencing it
		buffer = make([]byte, tr.cfg.RxBufferLength)
		nAvail = copy(buffer, d.Rest())
	}
}

type tcpImpl struct {
	noLocalAddrDialer
	localAddrRedialer
	streamRxLooper
}

type unixImpl struct {
	noLocalAddrDialer
	noLocalAddrRedialer
	streamRxLooper
}

func init() {
	implByNetwork["tcp"] = tcpImpl{}
	implByNetwork["tcp4"] = tcpImpl{}
	implByNetwork["tcp6"] = tcpImpl{}

	implByNetwork["unix"] = unixImpl{}
}
