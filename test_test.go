package ndn_test

import (
	"github.com/eric135/go-ndn/ndntestenv"
	"github.com/usnistgov/ndn-dpdk/core/testenv"
)

var (
	makeAR       = testenv.MakeAR
	bytesFromHex = testenv.BytesFromHex
	bytesEqual   = testenv.BytesEqual
	nameEqual    = ndntestenv.NameEqual
)
