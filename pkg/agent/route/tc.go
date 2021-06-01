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

package route

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	v1 "k8s.io/api/core/v1"
	utilnet "k8s.io/utils/net"
)

const (
	defaultHostGateway = "antrea-gw0"

	hashTableSize = uint32(256)

	priority = uint16(99)

	qdiscIngressId = uint32(0xffff)
	qdiscHtbId     = uint32(0xa)

	defaultBucket = 0x100
	defaultIndex  = 0
	defaultFlags  = uint8(0)

	tcpIPv4HandleIdOffset = uint32(0x100)
	udpIPv4HandleIdOffset = uint32(0x200)
	tcpIPv6HandleIdOffset = uint32(0x300)
	udpIPv6HandleIdOffset = uint32(0x400)
)

func cleanQdisc(nodeIPsMap map[int][]net.IP, defaultGatewayIndex int) error {
	for ifIndex := range nodeIPsMap {
		if ifIndex == 1 {
			continue
		}

		err := ingressQdiscDel(ifIndex)
		if err != nil {
			return err
		}
	}

	err := ingressQdiscDel(defaultGatewayIndex)
	if err != nil {
		return err
	}
	err = egressHtbQdiscDel(1, qdiscHtbId)
	if err != nil {
		return err
	}
	return nil
}

func getDefaultHostGatewayIndex() (int, error) {
	itf, err := net.InterfaceByName(defaultHostGateway)
	if err != nil {
		return 0, err
	}
	return itf.Index, nil
}

func getHandleOffset(isIPv6 bool, protocol v1.Protocol) uint32 {
	if isIPv6 && protocol == v1.ProtocolTCP {
		return tcpIPv6HandleIdOffset
	} else if isIPv6 && protocol == v1.ProtocolUDP {
		return udpIPv6HandleIdOffset
	} else if !isIPv6 && protocol == v1.ProtocolTCP {
		return tcpIPv4HandleIdOffset
	} else if !isIPv6 && protocol == v1.ProtocolUDP {
		return udpIPv4HandleIdOffset
	}
	return 0
}

func loopbackConfigAdd(nodeIPsMap map[int][]net.IP) error {
	loIndex := 1
	// Add egress qdisc to lo.
	err := egressHtbQdiscAdd(1, qdiscHtbId)
	if err != nil {
		return err
	}

	// Add two hash tables to the qdisc. In order to facilitate reading and remembering, interface index is used as the
	// suffix of hash table handle ID. A hash table has 256 buckets and every bucket can hold 4096 filters.
	// Theses two hash tables are used for distribute NodePort traffic from 127.0.0.1 or ::1. The suffix of handle ID is the
	// same as loopback index.
	err = hashTablesAdd(loIndex, qdiscHtbId, uint32(loIndex))
	if err != nil {
		return err
	}

	// Theses filters are used for distributing NodePort traffic destined for local IP addresses.
	for _, nodeIPs := range nodeIPsMap {
		for _, nodeIP := range nodeIPs {
			isIPv6 := utilnet.IsIPv6(nodeIP)
			tcpKeys := append(matchDstIP(nodeIP, isIPv6), matchTCP(isIPv6))
			udpKeys := append(matchDstIP(nodeIP, isIPv6), matchUDP(isIPv6))
			err = hashTableFiltersAdd(loIndex, isIPv6, hashDstPort, qdiscHtbId, uint32(loIndex), tcpKeys, udpKeys)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func ovsGatewayConfigAdd(gatewayIfIndex int, nodeIPsMap map[int][]net.IP) error {
	// Add ingress qdisc to antrea-gw0.
	err := ingressQdiscAdd(gatewayIfIndex)
	if err != nil {
		return err
	}

	// Note that, antrea-gw0 processes the reply NodePort traffic from multiple interfaces. In order to distinguish traffic
	// destined for different interfaces, add hash tables and corresponding filters for every interface.
	for ifIndex, nodeIPs := range nodeIPsMap {
		// Add two hash tables to the qdisc. In order to facilitate reading and remembering, interface index is used as the
		// suffix of hash table handle ID. A hash table has 256 buckets and every bucket can hold 4096 filters.
		err = hashTablesAdd(gatewayIfIndex, qdiscIngressId, uint32(ifIndex))
		if err != nil {
			return err
		}

		// A interface may have multiple IP addresses. For each IP address, add a filter whose source IP matches the
		// current IP address. Traffic will be distributed to corresponding buckets in the hash table created above according
		// to TCP/UDP source port. TCP/UDP source port has 16 bits, here the hash key is the first 8 bits, and the
		// last 8 bits are used for indexing a final filter in buckets.
		for _, nodeIP := range nodeIPs {
			isIPv6 := utilnet.IsIPv6(nodeIP)
			tcpKeys := append(matchSrcIP(nodeIP, isIPv6), matchTCP(isIPv6))
			udpKeys := append(matchSrcIP(nodeIP, isIPv6), matchUDP(isIPv6))
			err = hashTableFiltersAdd(gatewayIfIndex, isIPv6, hashSrcPort, qdiscIngressId, uint32(ifIndex), tcpKeys, udpKeys)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func generalInterfaceConfigAdd(ifIndex int, nodeIPs []net.IP) error {
	// Add ingress qdisc to the interface.
	err := ingressQdiscAdd(ifIndex)
	if err != nil {
		return err
	}

	// Add two hash tables to the qdisc. In order to facilitate reading and remembering, interface index is used as the
	// suffix of hash table handle ID. A hash table has 256 buckets and every bucket can hold 4096 filters.
	err = hashTablesAdd(ifIndex, qdiscIngressId, uint32(ifIndex))
	if err != nil {
		return err
	}

	// A interface may have multiple IP addresses. For each IP address, add a filter whose destination IP matches the
	// current IP address. Traffic will be distributed to corresponding buckets in the hash table created above according
	// to TCP/UDP destination port. TCP/UDP destination port has 16 bits, here the hash key is the first 8 bits, and the
	// last 8 bits are used for indexing a final filter in buckets.
	for _, nodeIP := range nodeIPs {
		isIPv6 := utilnet.IsIPv6(nodeIP)
		tcpKeys := append(matchDstIP(nodeIP, isIPv6), matchTCP(isIPv6))
		udpKeys := append(matchDstIP(nodeIP, isIPv6), matchUDP(isIPv6))
		err = hashTableFiltersAdd(ifIndex, isIPv6, hashDstPort, qdiscIngressId, uint32(ifIndex), tcpKeys, udpKeys)
		if err != nil {
			return err
		}
	}
	return nil
}

func hashTableFiltersAdd(ifIndex int, isIPv6 bool, hashFunc func(*netlink.TcU32Sel, bool), parent, handle uint32,
	tcpKeys, udpKeys []netlink.TcU32Key) error {
	tcpHandleId := getHandleOffset(isIPv6, v1.ProtocolTCP) + handle
	udpHandleId := getHandleOffset(isIPv6, v1.ProtocolUDP) + handle
	tcpSel := buildSelector(hashFunc, isIPv6, tcpKeys, defaultFlags)
	udpSel := buildSelector(hashFunc, isIPv6, udpKeys, defaultFlags)

	err := filterAdd(ifIndex, priority, parent, tcpHandleId, defaultBucket, defaultIndex, tcpSel, nil)
	if err != nil {
		return err
	}
	err = filterAdd(ifIndex, priority, parent, udpHandleId, defaultBucket, defaultIndex, udpSel, nil)
	if err != nil {
		return err
	}
	return nil
}

func hashTablesAdd(ifIndex int, parent, handle uint32) error {
	err := hashTableAdd(ifIndex, priority, parent, tcpIPv4HandleIdOffset+handle)
	if err != nil {
		return err
	}
	err = hashTableAdd(ifIndex, priority, parent, udpIPv4HandleIdOffset+handle)
	if err != nil {
		return err
	}
	err = hashTableAdd(ifIndex, priority, parent, tcpIPv6HandleIdOffset+handle)
	if err != nil {
		return err
	}
	err = hashTableAdd(ifIndex, priority, parent, udpIPv6HandleIdOffset+handle)
	if err != nil {
		return err
	}
	return nil
}

func ingressQdiscAdd(ifIndex int) error {
	qdisc := &netlink.Ingress{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifIndex,
			Parent:    netlink.HANDLE_INGRESS,
		},
	}

	err := netlink.QdiscAdd(qdisc)
	if err != nil {
		return fmt.Errorf("failed to add ingress qdisc for interface(index) %d: %s\n", ifIndex, err)
	}

	return nil
}

func ingressQdiscDel(ifIndex int) error {
	qdisc := &netlink.Ingress{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifIndex,
			Parent:    netlink.HANDLE_INGRESS,
		},
	}

	err := netlink.QdiscDel(qdisc)
	if err != nil {
		return fmt.Errorf("failed to delete ingress qdisc for interface(index) %d: %s\n", ifIndex, err)
	}

	return nil
}

func egressHtbQdiscAdd(ifIndex int, handle uint32) error {
	qdiscAttrs := netlink.QdiscAttrs{
		LinkIndex: ifIndex,
		Handle:    handle << 16,
		Parent:    netlink.HANDLE_ROOT,
	}
	htb := netlink.NewHtb(qdiscAttrs)

	err := netlink.QdiscAdd(htb)
	if err != nil {
		return fmt.Errorf("failed to add egress qdisc for interface(index) %d: %s\n", ifIndex, err)
	}

	return nil
}

func egressHtbQdiscDel(ifIndex int, handle uint32) error {
	qdiscAttrs := netlink.QdiscAttrs{
		LinkIndex: ifIndex,
		Handle:    handle << 16,
		Parent:    netlink.HANDLE_ROOT,
	}
	htb := netlink.NewHtb(qdiscAttrs)

	err := netlink.QdiscDel(htb)
	if err != nil {
		return fmt.Errorf("failed to delete egress qdisc for interface(index) %d: %s\n", ifIndex, err)
	}

	return nil
}

func hashSrcPort(tcU32Sel *netlink.TcU32Sel, isIPv6 bool) {
	off := int16(20)
	if isIPv6 {
		off = 40
	}
	tcU32Sel.Hoff = off
	tcU32Sel.Hmask = 0xff000000
}

func hashDstPort(tcU32Sel *netlink.TcU32Sel, isIPv6 bool) {
	off := int16(20)
	if isIPv6 {
		off = 40
	}
	tcU32Sel.Hoff = off
	tcU32Sel.Hmask = 0x0000ff00
}

func hashTableAdd(ifIndex int, priority uint16, parent, handle uint32) error {
	hashTable := &netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifIndex,
			Handle:    handle << 20,
			Protocol:  unix.ETH_P_IP,
			Parent:    parent << 16,
			Priority:  priority,
		},
		Divisor: hashTableSize,
	}

	if err := netlink.FilterAdd(hashTable); err != nil {
		return fmt.Errorf("failed to add hash table for interface(index) %d: %s\n", ifIndex, err)
	}

	return nil
}

func getFilterBucket(port uint32) uint32 {
	return (port & 0xff00) >> 8
}

func getFilterIndex(port uint32) uint32 {
	return port & 0xff
}

func buildSelector(hashFunc func(*netlink.TcU32Sel, bool), isIPv6 bool, keys []netlink.TcU32Key, flags uint8) *netlink.TcU32Sel {
	// It seems that netlink has memory leak
	keysTidy := make([]netlink.TcU32Key, len(keys))
	copy(keysTidy, keys)

	selector := new(netlink.TcU32Sel)
	selector.Keys = keysTidy
	selector.Nkeys = uint8(len(selector.Keys))
	selector.Flags = flags
	if hashFunc != nil {
		hashFunc(selector, isIPv6)
	}
	return selector
}

func matchDstIP(dst net.IP, isIPv6 bool) []netlink.TcU32Key {
	var keys []netlink.TcU32Key

	if isIPv6 {
		for i := 0; i < 4; i++ {
			key := netlink.TcU32Key{
				Mask:    0xffffffff,
				Val:     binary.BigEndian.Uint32(dst.To16()[i*4 : (i+1)*4]),
				Off:     24 + int32(i)*4,
				OffMask: 0,
			}
			keys = append(keys, key)
		}
	} else {
		key := netlink.TcU32Key{
			Mask:    0xffffffff,
			Val:     binary.BigEndian.Uint32(dst.To4()),
			Off:     16,
			OffMask: 0,
		}
		keys = append(keys, key)
	}

	return keys
}

func matchSrcIP(src net.IP, isIPv6 bool) []netlink.TcU32Key {
	var keys []netlink.TcU32Key

	if isIPv6 {
		for i := 0; i < 4; i++ {
			key := netlink.TcU32Key{
				Mask:    0xffffffff,
				Val:     binary.BigEndian.Uint32(src.To16()[i*4 : (i+1)*4]),
				Off:     8 + int32(i)*4,
				OffMask: 0,
			}
			keys = append(keys, key)
		}
	} else {
		key := netlink.TcU32Key{
			Mask:    0xffffffff,
			Val:     binary.BigEndian.Uint32(src.To4()),
			Off:     12,
			OffMask: 0,
		}
		keys = append(keys, key)
	}

	return keys
}

func matchDstPort(val uint32, isIPv6 bool) netlink.TcU32Key {
	off := int32(20)
	if isIPv6 {
		off = int32(40)
	}

	return netlink.TcU32Key{
		Mask:    0x0000ffff,
		Val:     val,
		Off:     off,
		OffMask: 0,
	}
}

func matchSrcPort(val uint32, isIPv6 bool) netlink.TcU32Key {
	off := int32(20)
	if isIPv6 {
		off = int32(40)
	}

	return netlink.TcU32Key{
		Mask:    0xffff0000,
		Val:     val << 16,
		Off:     off,
		OffMask: 0,
	}
}

func matchTCP(isIPv6 bool) netlink.TcU32Key {
	off := int32(8)
	mask := uint32(0x00ff0000)
	val := uint32(0x6) << 16

	if isIPv6 {
		off = int32(4)
		mask = uint32(0x0000ff00)
		val = uint32(0x6) << 8
	}

	return netlink.TcU32Key{
		Mask:    mask,
		Val:     val,
		Off:     off,
		OffMask: 0,
	}
}

func matchUDP(isIPv6 bool) netlink.TcU32Key {
	off := int32(8)
	mask := uint32(0x00ff0000)
	val := uint32(0x11) << 16

	if isIPv6 {
		off = int32(4)
		mask = uint32(0x0000ff00)
		val = uint32(0x6) << 8
	}

	return netlink.TcU32Key{
		Mask:    mask,
		Val:     val,
		Off:     off,
		OffMask: 0,
	}
}

func actionRedirect(ifIndex int, mirredAction netlink.MirredAct) netlink.Action {
	return &netlink.MirredAction{
		ActionAttrs: netlink.ActionAttrs{
			Action: netlink.TC_ACT_STOLEN,
		},
		MirredAction: mirredAction,
		Ifindex:      ifIndex,
	}
}

func filterAdd(ifIndex int, priority uint16, parent, link, bucket, index uint32, sel *netlink.TcU32Sel, actions []netlink.Action) error {
	filter := &netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifIndex,
			Parent:    parent << 16,
			Protocol:  unix.ETH_P_IP,
			Priority:  priority,
		},
		Link:    link << 20,
		Sel:     sel,
		Actions: actions,
	}
	if bucket != defaultBucket {
		filter.Hash = link<<20 | bucket<<12
		filter.Link = 0
	}
	if index != defaultIndex {
		filter.FilterAttrs.Handle = index
	}

	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("failed to add fitler for interface(index) %d: %s\n", ifIndex, err)
	}
	return nil
}

func filterDelete(ifIndex int, priority uint16, parent, link, bucket, index uint32) error {
	filter := &netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifIndex,
			Parent:    parent << 16,
			Protocol:  unix.ETH_P_IP,
			Priority:  priority,
			Handle:    link<<20 | bucket<<12 | index,
		},
	}

	if err := netlink.FilterDel(filter); err != nil {
		return fmt.Errorf("failed to delete fitler for interface(index) %d: %s\n", ifIndex, err)
	}
	return nil
}
