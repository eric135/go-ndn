// +build !linux !amd64

package gqlmgmt

import (
	"errors"

	"github.com/eric135/go-ndn/mgmt"
)

var errNoOpenFace = errors.New("OpenFace not supported on this platform")

// OpenFace invokes OpenMemif with default settings.
func (c *Client) OpenFace() (mgmt.Face, error) {
	return nil, errNoOpenFace
}
