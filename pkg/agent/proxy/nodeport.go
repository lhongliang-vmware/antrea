// Copyright 2021 Antrea Authors
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

package proxy

import (
	"fmt"
	"net"

	netutils "k8s.io/utils/net"
)

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
