// Package ndntestenv contains helper functions to validate NDN packets in test code.
package ndntestenv

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/eric135/go-ndn"
	"github.com/eric135/go-ndn/l3"
	"github.com/usnistgov/ndn-dpdk/core/testenv"
)

// L3FaceTester tests L3Face or Transport.
type L3FaceTester struct {
	Count            int
	LossTolerance    float64
	InterestInterval time.Duration
	CloseDelay       time.Duration
}

func (c *L3FaceTester) applyDefaults() {
	if c.Count <= 0 {
		c.Count = 1000
	}
	if c.LossTolerance <= 0.0 {
		c.LossTolerance = 0.05
	}
	if c.InterestInterval <= 0 {
		c.InterestInterval = 1 * time.Millisecond
	}
	if c.CloseDelay <= 0 {
		c.CloseDelay = 100 * time.Millisecond
	}
}

// CheckTransport tests a pair of connected Transport.
func (c *L3FaceTester) CheckTransport(t *testing.T, trA, trB l3.Transport) {
	_, require := testenv.MakeAR(t)
	faceA, e := l3.NewFace(trA)
	require.NoError(e)
	faceB, e := l3.NewFace(trB)
	require.NoError(e)
	c.CheckL3Face(t, faceA, faceB)
}

// CheckL3Face tests a pair of connected L3Face.
func (c *L3FaceTester) CheckL3Face(t *testing.T, faceA, faceB l3.Face) {
	c.applyDefaults()
	assert, require := testenv.MakeAR(t)

	var wg sync.WaitGroup
	wg.Add(5)
	faceA.OnStateChange(func(st l3.TransportState) {
		if st == l3.TransportClosed {
			wg.Done()
		}
	})
	faceB.OnStateChange(func(st l3.TransportState) {
		if st == l3.TransportClosed {
			wg.Done()
		}
	})

	doneA := make(chan bool)

	go func() {
		rxB := faceB.Rx()
		txB := faceB.Tx()
		for {
			select {
			case <-doneA:
				close(txB)
				wg.Done()
				return

			case packet, ok := <-rxB:
				if !ok {
					break
				}
				require.Len(packet.Lp.PitToken, 8)
				require.NotNil(packet.Interest)
				data := ndn.MakeData(*packet.Interest)
				txB <- data
			}
		}
	}()

	nData := 0
	hasPacket := make([]bool, c.Count)
	go func() {
		for packet := range faceA.Rx() {
			require.Len(packet.Lp.PitToken, 8)
			token := ndn.PitTokenToUint(packet.Lp.PitToken)
			assert.NotNil(packet.Data)
			nData++

			require.LessOrEqual(token, uint64(c.Count), "%d", token)
			assert.False(hasPacket[token], "%d", token)
			hasPacket[token] = true
		}
		wg.Done()
	}()

	go func() {
		txA := faceA.Tx()
		for i := 0; i < c.Count; i++ {
			interest := ndn.MakeInterest(fmt.Sprintf("/A/%d", i))
			var packet ndn.Packet
			packet.Interest = &interest
			packet.Lp.PitToken = ndn.PitTokenFromUint(uint64(i))
			txA <- &packet
			time.Sleep(c.InterestInterval)
		}

		time.Sleep(c.CloseDelay)
		close(txA)
		doneA <- true
		wg.Done()
	}()

	wg.Wait()
	assert.InEpsilon(c.Count, nData, c.LossTolerance)
}
