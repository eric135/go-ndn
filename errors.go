package ndn

import (
	"errors"
)

// Simple error conditions.
var (
	ErrFragment      = errors.New("bad fragment")
	ErrL3Type        = errors.New("unknown L3 packet type")
	ErrComponentType = errors.New("NameComponent TLV-TYPE out of range")
	ErrNonceLen      = errors.New("Nonce wrong length")
	ErrLifetime      = errors.New("InterestLifetime out of range")
	ErrHopLimit      = errors.New("HopLimit out of range")
	ErrParamsDigest  = errors.New("bad ParamsDigest")
	ErrSigType       = errors.New("bad SigType")
	ErrKeyLocator    = errors.New("bad KeyLocator")
	ErrSigNonce      = errors.New("bad SigNonce")
	ErrSigValue      = errors.New("bad SigValue")
)
