//go:build windows
// +build windows

/*
Copyright © 2022 SUSE LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/rancher-sandbox/rancher-desktop-host-resolver/pkg/helper" //nolint:ignore
	"github.com/rancher-sandbox/rancher-desktop-host-resolver/test/testdns"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

var (
	// for now we use this maybe this can be an env var from test
	wslDistroName = "Ubuntu"
	testSrvAddr   = "127.0.0.1"
	dnsPort       = "53"
)

func TestLookupARecords(t *testing.T) { //nolint // TODO: break down the func
	tmpDir, err := ioutil.TempDir("", "e2e_test_")
	require.NoError(t, err, "Failed creating temp dir")
	defer os.RemoveAll(tmpDir)
	t.Logf("Using %v as a temporary directory", tmpDir)

	dnsInfs, err := helper.GetDNSInterfaces()
	require.NoError(t, err, "Failed getting DNS addrs associated to interfaces")
	// This is to cache all the exsisting DNS addresses
	guidToDNSAddr, err := cacheExsitingDNSAddrs(dnsInfs)
	require.NoError(t, err, "Failed caching exsisting DNS server addresses")
	t.Log("Updating network interfaces with test DNS server addr")
	// Update the dns addrs to test server
	testDNSAddr := netip.MustParseAddr(testSrvAddr)
	testDNSAddrIPv6 := netip.IPv6Unspecified()
	for _, addr := range dnsInfs {
		// Set IPv4 DNS
		err := addr.LUID.SetDNS(winipcfg.AddressFamily(windows.AF_INET), []netip.Addr{testDNSAddr}, []string{})
		require.NoErrorf(t, err, "Failed setting DNS server for: %v", addr.FriendlyName())
		// Set IPv6 DNS to unspecified so DNS lookup will not be bypassed
		err = addr.LUID.SetDNS(windows.AF_INET6, []netip.Addr{testDNSAddrIPv6}, []string{})
		require.NoErrorf(t, err, "Failed setting DNS server for: %v", addr.FriendlyName())
	}
	defer func() {
		t.Log("Restoring DNS servers back to the original state")
		for _, addr := range dnsInfs {
			addrGUID, err := addr.LUID.GUID()
			require.NoErrorf(t, err, "Failed getting interface GUID for: %v", addr.FriendlyName())
			if dnsAddr, ok := guidToDNSAddr[addrGUID.String()]; ok {
				err := addr.LUID.SetDNS(windows.AF_INET, dnsAddr, []string{})
				require.NoErrorf(t, err, "Failed setting DNS server IPv4 addrs for: %v", addr.FriendlyName())
				err = addr.LUID.SetDNS(windows.AF_INET6, dnsAddr, []string{})
				require.NoErrorf(t, err, "Failed setting DNS server IPv6 addrs for: %v", addr.FriendlyName())
			}
		}
	}()

	t.Log("building host-resolver host binary")
	//TODO: make paths better
	err = buildBinaries("../../...", "windows", tmpDir)
	require.NoError(t, err, "Failed building host-resolver.exe")

	t.Log("building host-resolver peer binary")
	//TODO: make paths better
	err = buildBinaries("../../...", "linux", tmpDir)
	require.NoError(t, err, "Failed building host-resolver")

	//TODO: make paths better
	aRecords := testdns.LoadRecords("../testdata/test-300.csv")

	tcpHandler := testdns.NewHandler(false)
	tcpHandler.Arecords = aRecords

	udpHandler := testdns.NewHandler(true)
	udpHandler.Arecords = aRecords

	testServer := testdns.Server{
		Addr:       testSrvAddr,
		TCPPort:    dnsPort,
		UDPPort:    dnsPort,
		TCPHandler: tcpHandler,
		UDPHandler: udpHandler,
	}
	t.Log("starting test upstream DNS server")
	// TODO: this needs a shutdown
	go testServer.Run()

	t.Logf("starting host-resolver peer process in wsl [%v]", wslDistroName)
	peerCmd := exec.Command("wsl", "--user", "root",
		"--distribution", wslDistroName,
		"--exec", "./rancher-desktop-host-resolver", "vsock-peer")
	peerCmd.Dir = tmpDir
	peerCmd.Stdout = os.Stdout
	peerCmd.Stderr = os.Stderr
	err = peerCmd.Start()
	require.NoError(t, err, "Starting host-resolver peer process faild")

	t.Log("starting host-resolver host process")
	hostCmd := exec.Command( //nolint:gosec // no security implications here
		fmt.Sprintf("%v/rancher-desktop-host-resolver.exe", tmpDir), "vsock-host",
		"--upstream-servers", fmt.Sprintf("[%v]", testSrvAddr))
	hostCmd.Stdout = os.Stdout
	hostCmd.Stderr = os.Stderr
	err = hostCmd.Start()
	require.NoError(t, err, "Starting host-resolver host process faild")

	t.Log("building dns hammer binary")
	err = buildBinaries("../...", "linux", tmpDir)
	require.NoError(t, err, "Failed building dnsHammer")

	err = copyTestData("../testdata/test-300.csv", fmt.Sprintf("%s/test-300.csv", tmpDir))
	require.NoError(t, err, "copying test data file")
	// we need something smarter to determine if the processes are running
	// maybe health check endpoint?
	time.Sleep(time.Second * 5)
	t.Logf("running dns hammer test process in wsl [%v]", wslDistroName)
	dnsSrvAddr := net.JoinHostPort(testSrvAddr, dnsPort)
	runTestCmd := exec.Command(
		"wsl",
		"--user", "root",
		"--distribution", wslDistroName,
		"--exec", "./test", "dnshammer",
		"--server-address", dnsSrvAddr,
		"--rr-type", "A=test-300.csv")
	runTestCmd.Dir = tmpDir
	runTestCmd.Stdout = os.Stdout
	runTestCmd.Stderr = os.Stderr
	err = runTestCmd.Run()
	require.NoError(t, err, "Running dns hammer against the peer process faild")
	_ = hostCmd.Process.Kill()
	_ = peerCmd.Process.Kill()
	_ = runTestCmd.Process.Kill()
}

// TODO (Nino-K): this should be replaced by CI
func buildBinaries(path, goos, tmpDir string) error {
	buildCmd := exec.Command("go", "build", "-o", tmpDir, path)
	buildCmd.Env = os.Environ()
	buildCmd.Env = append(buildCmd.Env, fmt.Sprintf("GOOS=%s", goos), "GOARCH=amd64")
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr

	return buildCmd.Run()
}

func copyTestData(src, dst string) error {
	bytesRead, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, bytesRead, 0600)
}

func cacheExsitingDNSAddrs(adapterAddrs []*winipcfg.IPAdapterAddresses) (map[string][]netip.Addr, error) {
	var adapterAddrsCopy = make([]*winipcfg.IPAdapterAddresses, len(adapterAddrs))
	copy(adapterAddrsCopy, adapterAddrs)
	guidToDNSAddrs := make(map[string][]netip.Addr)
	for _, a := range adapterAddrsCopy {
		guid, err := a.LUID.GUID()
		if err != nil {
			return nil, err
		}
		dnsAddrs, err := a.LUID.DNS()
		if err != nil {
			return nil, err
		}
		guidToDNSAddrs[guid.String()] = dnsAddrs
	}
	return guidToDNSAddrs, nil
}
