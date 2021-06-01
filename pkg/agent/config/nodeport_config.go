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

package config

import (
	"k8s.io/klog/v2"
	"net"
)

// GetAvailableNodePortAddresses gets available NodePort addresses with config.
func GetAvailableNodePortAddresses(nodePortAddressesFromConfig []string) (map[int][]net.IP, error) {
	var nodePortIPNets []*net.IPNet
	nodePortAddresses := make(map[int][]net.IP)
	_, ipv6LinkLocalNet, _ := net.ParseCIDR("fe80::/64")

	// Convert every NodePort address to IPNet.
	for _, nodePortAddress := range nodePortAddressesFromConfig {
		_, ipNet, _ := net.ParseCIDR(nodePortAddress)
		nodePortIPNets = append(nodePortIPNets, ipNet)
	}

	// Get all interfaces.
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, itf := range interfaces {
		// Get all IPs of every interface
		addresses, err := itf.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addresses {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				return nil, err
			}
			if ipv6LinkLocalNet.Contains(ip) {
				continue
			}
			// If the NodePort IPNet that is converted from config contains the current IP, then the current IP is available.
			var contains bool
			for _, nodePortIPNet := range nodePortIPNets {
				if nodePortIPNet.Contains(ip) {
					contains = true
					break
				}
			}
			// If option 'NodePortAddresses' is not specified in config, every IP address will be NodePort IP address.
			if len(nodePortIPNets) == 0 || contains {
				nodePortAddresses[itf.Index] = append(nodePortAddresses[itf.Index], ip)
			}
		}
	}

	if len(nodePortAddresses) == 0 {
		klog.Warningln("No qualified NodePort IP address found.")
	}
	return nodePortAddresses, nil
}
