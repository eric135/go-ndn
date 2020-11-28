package memiftransport_test

import (
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"testing"
	"time"

	"github.com/eric135/go-ndn/memiftransport"
	"github.com/eric135/go-ndn/ndntestenv"
)

func TestTransport(t *testing.T) {
	assert, require := makeAR(t)

	dir, e := ioutil.TempDir("", "memiftransport-test")
	require.NoError(e)
	defer os.RemoveAll(dir)

	helper := exec.Command(os.Args[0], memifbridgeArg, dir)
	helperIn, e := helper.StdinPipe()
	require.NoError(e)
	helper.Stdout = os.Stdout
	helper.Stderr = os.Stderr
	require.NoError(helper.Start())
	time.Sleep(1 * time.Second)

	trA, e := memiftransport.New(memiftransport.Locator{
		SocketName: path.Join(dir, "memifA.sock"),
		ID:         1216,
	})
	require.NoError(e)
	trB, e := memiftransport.New(memiftransport.Locator{
		SocketName: path.Join(dir, "memifB.sock"),
		ID:         2643,
	})
	require.NoError(e)

	var c ndntestenv.L3FaceTester
	c.CheckTransport(t, trA, trB)

	helperIn.Write([]byte("."))
	assert.NoError(helper.Wait())
}

const memifbridgeArg = "memifbridge"

func memifbridgeHelper() {
	dir := os.Args[2]
	var locA, locB memiftransport.Locator
	locA.SocketName = path.Join(dir, "memifA.sock")
	locA.ID = 1216
	locB.SocketName = path.Join(dir, "memifB.sock")
	locB.ID = 2643

	bridge, e := memiftransport.NewBridge(locA, locB, true)
	if e != nil {
		panic(e)
	}

	io.ReadAtLeast(os.Stdin, make([]byte, 1), 1)
	bridge.Close()
}
