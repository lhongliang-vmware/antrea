// Copyright 2019 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build linux

package util

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"
	netutils "k8s.io/utils/net"
)

// GetNetLink returns dev link from name.
func GetNetLink(dev string) netlink.Link {
	link, err := netlink.LinkByName(dev)
	if err != nil {
		klog.Errorf("Failed to find dev %s: %v", dev, err)
		return nil
	}
	return link
}

// GetNSPeerDevBridge returns peer device and its attached bridge (if applicable)
// for device dev in network space indicated by nsPath
func GetNSPeerDevBridge(nsPath, dev string) (*net.Interface, string, error) {
	var peerIdx int
	netNS, err := ns.GetNS(nsPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get NS for path %s: %w", nsPath, err)
	}
	if err := netNS.Do(func(_ ns.NetNS) error {
		_, peerIdx, err = ip.GetVethPeerIfindex(dev)
		if err != nil {
			return fmt.Errorf("failed to get peer idx for dev %s in container %s: %w", dev, nsPath, err)
		}
		return nil
	}); err != nil {
		return nil, "", err
	}

	peerIntf, err := net.InterfaceByIndex(peerIdx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get interface for idx %d: %w", peerIdx, err)
	}
	peerLink, err := netlink.LinkByIndex(peerIdx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get link for idx %d: %w", peerIdx, err)
	}

	// not attached to a bridge.
	if peerLink.Attrs().MasterIndex <= 0 {
		return peerIntf, "", nil
	}

	bridgeLink, err := netlink.LinkByIndex(peerLink.Attrs().MasterIndex)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get master link for dev %s: %w", peerLink.Attrs().Name, err)
	}
	bridge, ok := bridgeLink.(*netlink.Bridge)
	if !ok {
		// master link is not bridge
		return peerIntf, "", nil
	}
	return peerIntf, bridge.Name, nil
}

// GetNSDevInterface returns interface of dev in namespace nsPath.
func GetNSDevInterface(nsPath, dev string) (*net.Interface, error) {
	netNS, err := ns.GetNS(nsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get NS for path %s: %w", nsPath, err)
	}
	var intf *net.Interface
	if err := netNS.Do(func(_ ns.NetNS) error {
		intf, err = net.InterfaceByName(dev)
		if err != nil {
			return fmt.Errorf("failed to get interface %s in container %s: %w", dev, nsPath, err)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return intf, nil
}

// GetNSPath returns the path of the specified netns.
func GetNSPath(netnsName string) (string, error) {
	netNS, err := ns.GetNS(netnsName)
	if err != nil {
		return "", fmt.Errorf("failed to open netns %s: %v", netnsName, err)
	}
	defer netNS.Close()
	return netNS.Path(), nil
}

func SetLinkUp(name string) (net.HardwareAddr, int, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return nil, 0, newLinkNotFoundError(name)
		} else {
			return nil, 0, err
		}
	}
	// Set host gateway interface up.
	if err := netlink.LinkSetUp(link); err != nil {
		klog.Errorf("Failed to set host link for %s up: %v", name, err)
		return nil, 0, err
	}
	mac := link.Attrs().HardwareAddr
	index := link.Attrs().Index
	return mac, index, nil
}

func addrSliceDifference(s1, s2 []netlink.Addr) []*netlink.Addr {
	var diff []*netlink.Addr

	for i, e1 := range s1 {
		found := false
		for _, e2 := range s2 {
			if e1.Equal(e2) {
				found = true
				break
			}
		}
		if !found {
			diff = append(diff, &s1[i])
		}
	}

	return diff
}

// ConfigureLinkAddresses adds the provided addresses to the interface identified by index idx, if
// they are missing from the interface. Any other existing address already configured for the
// interface will be removed, unless it is a link-local address.
func ConfigureLinkAddresses(idx int, ipNets []*net.IPNet) error {
	// No need to check the error here, since the link is found in previous steps.
	link, _ := netlink.LinkByIndex(idx)
	ifaceName := link.Attrs().Name
	var newAddrs []netlink.Addr
	for _, ipNet := range ipNets {
		newAddrs = append(newAddrs, netlink.Addr{IPNet: ipNet, Label: ""})
	}

	allAddrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to query address list for interface %s: %v", ifaceName, err)
	}
	// Remove link-local address from list
	addrs := make([]netlink.Addr, 0, len(allAddrs))
	for _, addr := range allAddrs {
		if !addr.IP.IsLinkLocalUnicast() {
			addrs = append(addrs, addr)
		}
	}

	addrsToAdd := addrSliceDifference(newAddrs, addrs)
	addrsToRemove := addrSliceDifference(addrs, newAddrs)

	if len(addrsToAdd) == 0 && len(addrsToRemove) == 0 {
		klog.V(2).Infof("IP configuration for interface %s does not need to change", ifaceName)
		return nil
	}

	for _, addr := range addrsToRemove {
		klog.V(2).Infof("Removing address %v from interface %s", addr, ifaceName)
		if err := netlink.AddrDel(link, addr); err != nil {
			return fmt.Errorf("failed to remove address %v from interface %s: %v", addr, ifaceName, err)
		}
	}

	for _, addr := range addrsToAdd {
		klog.V(2).Infof("Adding address %v to interface %s", addr, ifaceName)
		if err := netlink.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("failed to add address %v to interface %s: %v", addr, ifaceName, err)
		}
	}

	return nil
}

// ListenLocalSocket creates a listener on a Unix domain socket.
func ListenLocalSocket(address string) (net.Listener, error) {
	// remove before bind to avoid "address already in use" errors
	_ = os.Remove(address)

	if err := os.MkdirAll(filepath.Dir(address), 0750); err != nil {
		klog.Fatalf("Failed to create directory %s: %v", filepath.Dir(address), err)
	}
	listener, err := listenUnix(address)
	if err != nil {
		return nil, err
	}
	err = os.Chmod(address, 0750)
	if err != nil {
		klog.Fatalf("Failed to change permissions for socket file %s: %v", address, err)
	}
	return listener, nil
}

// DialLocalSocket connects to a Unix domain socket.
func DialLocalSocket(address string) (net.Conn, error) {
	return dialUnix(address)
}

// GetAvailableNodePortIPs gets available NodePort IP addresses with config.
func GetAvailableNodePortIPs(nodePortIPsFromConfig []string, gateway string) (map[int][]net.IP, map[int][]net.IP, error) {
	var nodePortIPNets []*net.IPNet
	nodePortIPMap := make(map[int][]net.IP)
	nodePortIPv6Map := make(map[int][]net.IP)
	_, ipv6LinkLocalNet, _ := net.ParseCIDR("fe80::/64")

	// Convert every NodePort address to IPNet.
	for _, nodePortIP := range nodePortIPsFromConfig {
		_, ipNet, _ := net.ParseCIDR(nodePortIP)
		nodePortIPNets = append(nodePortIPNets, ipNet)
	}

	// Get all interfaces.
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for _, itf := range interfaces {
		// Get all IPs of every interface
		addrs, err := itf.Addrs()
		if err != nil {
			return nil, nil, err
		}
		for _, addr := range addrs {
			ip, _, _ := net.ParseCIDR(addr.String())
			if ipv6LinkLocalNet.Contains(ip) {
				continue // Skip IPv6 link local address
			}

			// If the NodePort IPNet that is converted from config contains the current IP address, then the current IP
			// address from config is available.
			var contains bool
			for _, nodePortIPNet := range nodePortIPNets {
				if nodePortIPNet.Contains(ip) {
					contains = true
					break
				}
			}
			// If option 'nodePortAddresses' is not specified in config, every IPv4/IPv6 address will be NodePort IP address.
			// An interface may has more than one IPv4/IPv6 addresses for NodePort.
			// Interface index will be used to generate Linux TC filter chain and handle ID.
			if len(nodePortIPNets) == 0 || contains {
				if netutils.IsIPv6(ip) {
					nodePortIPv6Map[itf.Index] = append(nodePortIPv6Map[itf.Index], ip)
				} else {
					nodePortIPMap[itf.Index] = append(nodePortIPMap[itf.Index], ip)
				}
			}
		}
	}
	// Gateway IP addresses can't be as NodePort IP addresses.
	gatewayItf, err := net.InterfaceByName(gateway)
	if err != nil {
		return nil, nil, err
	}
	delete(nodePortIPMap, gatewayItf.Index)

	if len(nodePortIPMap) == 0 {
		return nil, nil, fmt.Errorf("no qualified NodePort IPv4 addresses was found")
	}
	if len(nodePortIPv6Map) == 0 {
		return nil, nil, fmt.Errorf("no qualified NodePort IPv6 addresses was found")
	}
	return nodePortIPMap, nodePortIPv6Map, nil
}
