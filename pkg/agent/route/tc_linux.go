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
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

const (
	qdiscHandleIngress = uint32(0xffff)
	qdiscHandleEgress  = uint32(0xa)
	ingress            = "ingress"
	egress             = "egress"

	devLoopback     = "lo"
	loopbackIfIndex = 1

	protoIPv4Str = "ipv4"
	protoIPv6Str = "ipv6"
	protoTCPStr  = "tcp"
	protoUDPStr  = "udp"
	protoSCTPStr = "sctp"

	filterIPv4PriorityNormal = 104
	filterIPv6PriorityNormal = 106
	filterIPv4PriorityHigh   = 4
	filterIPv6PriorityHigh   = 6

	zeroMac = "00:00:00:00:00:00"

	filterNotFound1 = "Filter with specified priority/protocol not found"
	filterNotFound2 = "Cannot find specified filter chain"
	filterNotFound3 = "Specified filter handle not found"
)

func getNameByIndex(ifIndex int) string {
	dev, _ := net.InterfaceByIndex(ifIndex)
	return dev.Name
}

func getIndexByName(name string) int {
	dev, _ := net.InterfaceByName(name)
	return dev.Index
}

func getL3ProtoStr(proto int) string {
	var l3ProtoStr string
	if proto == unix.IPPROTO_IP {
		l3ProtoStr = protoIPv4Str
	} else if proto == unix.IPPROTO_IPV6 {
		l3ProtoStr = protoIPv6Str
	}

	return l3ProtoStr
}

func getL3Proto(addr net.IP) int {
	var proto int
	if !utilnet.IsIPv6(addr) {
		proto = unix.IPPROTO_IP
	} else {
		proto = unix.IPPROTO_IPV6
	}
	return proto
}

func getL4ProtoStr(proto int) string {
	var l4ProtoStr string
	if proto == unix.IPPROTO_TCP {
		l4ProtoStr = protoTCPStr
	} else if proto == unix.IPPROTO_UDP {
		l4ProtoStr = protoUDPStr
	} else if proto == unix.IPPROTO_SCTP {
		l4ProtoStr = protoSCTPStr
	}
	return l4ProtoStr
}

func getPriority(proto int, ifIndex int) int {
	var priority int
	if proto == unix.IPPROTO_IP {
		if ifIndex == loopbackIfIndex {
			return filterIPv4PriorityHigh
		} else {
			return filterIPv4PriorityNormal
		}
	} else if proto == unix.IPPROTO_IPV6 {
		if ifIndex == loopbackIfIndex {
			return filterIPv6PriorityHigh
		} else {
			return filterIPv6PriorityNormal
		}
	}
	return priority
}

func commandRun(argsStr string) (string, error) {
	klog.V(4).Infof("run command \"%s\"\n", argsStr)
	args := strings.Split(argsStr, " ")
	cmd := exec.Command(args[0], args[1:]...) //nolint:gosec

	var stdout bytes.Buffer
	cmd.Stderr = &stdout
	cmd.Stdout = &stdout
	err := cmd.Run()
	if err != nil {
		return string(stdout.Bytes()), fmt.Errorf("run command \"%s\" with err: %v", argsStr, err)
	}

	return string(stdout.Bytes()), nil
}

// qdiscAdd adds a qdisc to an interface.
func qdiscAdd(handle uint32, ifIndex int) error {
	dev := getNameByIndex(ifIndex)

	var cmd string
	if handle == qdiscHandleIngress {
		cmd = fmt.Sprintf("tc qdisc add dev %s ingress", dev)
	} else {
		cmd = fmt.Sprintf("tc qdisc add dev %s root handle %x: htb", dev, handle)
	}

	_, err := commandRun(cmd)
	if err != nil {
		return err
	}
	return nil
}

// qdiscDel deletes a qdisc from an interface.
func qdiscDel(handle uint32, dev string) error {
	var cmd string
	if handle == qdiscHandleIngress {
		cmd = fmt.Sprintf("tc qdisc del dev %s ingress", dev)
	} else {
		cmd = fmt.Sprintf("tc qdisc del dev %s root handle %x: htb", dev, handle)
	}
	_, err := commandRun(cmd)
	if err != nil {
		return err
	}
	return nil
}

// qdiscCheck checks that whether there is a demand qdisc and clears other unneeded qdiscs.
func qdiscCheck(handle uint32, ifIndex int) (bool, error) {
	var exist bool
	var keyWord string
	dev := getNameByIndex(ifIndex)

	cmd := fmt.Sprintf("tc qdisc show dev %s", dev)
	output, err := commandRun(cmd)
	if err != nil {
		return false, err
	}

	if handle == qdiscHandleIngress {
		keyWord = fmt.Sprintf("ingress %x:", handle)
	} else {
		keyWord = fmt.Sprintf("htb %x:", handle)
	}

	qdiscs := strings.Split(strings.TrimRight(output, string('\n')), string('\n'))
	for _, qdisc := range qdiscs {
		if strings.Contains(qdisc, keyWord) {
			exist = true
		} else {
			// Clean other unneeded qdiscs
			// In general, qdisc output like below. Split the qdisc string into array and get the handle number at index 2.
			// qdisc fq_codel 0: root refcnt 2 limit 10240p flows 1024 quantum 1514 target 5.0ms interval 100.0ms memory_limit 32Mb ecn
			// qdisc ingress ffff: parent ffff:fff1 ----------------

			arr := strings.Split(qdisc, " ")
			handle, _ := strconv.ParseUint(arr[2][:len(arr[2])-1], 16, 32)
			if handle == 0 { // The qdisc with handle number 0 is the default qdisc and cannot be cleared.
				continue
			}
			err = qdiscDel(uint32(handle), dev)
			if err != nil {
				klog.Warningf("clear unneeded qdisc '%s' with error: %v", qdisc, err)
			}
		}
	}

	return exist, nil
}

// loopbackFiltersAdd creates Linux TC filter for loopback. Currently, a filter is created for every available NodePort IP
// address and NodePort protocol/port. Note that, this is not the best design. When a NodePort is added, assumed that
// there are 20 available NodePort IP addresses, this function will be called 20 times.
// TODO: Add basic filters matching NodePort IP addresses as destination IP, then the matched traffic goto a target chain.
// TODO: Add filters matching NodePort destination protocol/port.
func loopbackFiltersAdd(ifIndex int, l4Protocol int, dstPort uint32, dstIPs []net.IP, gateway string, gatewayMAC string) error {
	l4ProtoStr := getL4ProtoStr(l4Protocol)
	for index, dstIP := range dstIPs {
		l3Proto := getL3Proto(dstIP)
		l3ProtoStr := getL3ProtoStr(l3Proto)
		priority := getPriority(l3Proto, loopbackIfIndex)
		handle := index<<28 | ifIndex<<24 | l3Proto&0xf<<20 | l4Protocol&0xf<<16 | int(dstPort)

		exist, err := filterCheck(devLoopback, qdiscHandleEgress, priority, l3ProtoStr, 0, handle)
		if err != nil {
			return err
		}
		if !exist {
			cmd := fmt.Sprintf("tc filter add dev %s parent %x:0 prio %d", devLoopback, qdiscHandleEgress, priority)
			cmd = fmt.Sprintf("%s protocol %s chain %d handle %d flower", cmd, l3ProtoStr, 0, handle)
			cmd = fmt.Sprintf("%s ip_proto %s dst_ip %s dst_port %d", cmd, l4ProtoStr, dstIP.String(), dstPort)
			cmd = fmt.Sprintf("%s action skbmod set smac %s pipe", cmd, gatewayMAC)
			cmd = fmt.Sprintf("%s action mirred egress redirect dev %s", cmd, gateway)
			_, err = commandRun(cmd)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// loopbackFiltersDel deletes Linux TC filter for loopback.
func loopbackFiltersDel(ifIndex int, l4Protocol int, dstPort uint32, dstIPs []net.IP) error {
	for index, dstIP := range dstIPs {
		l3Proto := getL3Proto(dstIP)
		l3ProtoStr := getL3ProtoStr(l3Proto)
		priority := getPriority(l3Proto, loopbackIfIndex)
		handle := index<<28 | ifIndex<<24 | l3Proto&0xf<<20 | l4Protocol&0xf<<16 | int(dstPort)

		cmd := fmt.Sprintf("tc filter del dev %s parent %x:0 prio %d", devLoopback, qdiscHandleEgress, priority)
		cmd = fmt.Sprintf("%s protocol %s chain %d handle %d flower", cmd, l3ProtoStr, 0, handle)
		_, err := commandRun(cmd)
		if err != nil {
			return err
		}
	}

	return nil
}

// interfaceFiltersAdd creates Linux TC filter for general interfaces(not including loopback and Antrea gateway. Like loopback,
// this is also not the best design.
// TODO: as loopback.
func interfaceFiltersAdd(ifIndex int, l4Proto int, dstPort uint32, dstIPs []net.IP, gateway string) error {
	if ifIndex == loopbackIfIndex {
		return nil
	}
	dev := getNameByIndex(ifIndex)
	l4ProtoStr := getL4ProtoStr(l4Proto)

	// An interface may have more than one IP addresses used for NodePort.
	for index, dstIP := range dstIPs {
		l3Proto := getL3Proto(dstIP)
		l3ProtoStr := getL3ProtoStr(l3Proto)
		priority := getPriority(l3Proto, ifIndex)
		handle := index<<24 | l3Proto&0xf<<20 | l4Proto&0xf<<16 | int(dstPort)
		// Assumed that dstPort is 0x0001, index is 0x1, all possible handle are:
		// L3 Proto    l4 Proto     handle
		// IPv4(0x0)   TCP(0x6)     0x1060001
		// IPv4(0x0)   UDP(0x11)    0x1010001
		// IPv4(0x0)   SCTP(0x84)   0x1410001
		// IPv6(0x29)  TCP(0x6)     0x1960001
		// IPv6(0x29)  UDP(0x11)    0x1910001
		// IPv6(0x29)  SCTP(0x84)   0x1940001

		exist, err := filterCheck(dev, qdiscHandleIngress, priority, l3ProtoStr, 0, handle)
		if err != nil {
			return err
		}
		if !exist {
			cmd := fmt.Sprintf("tc filter add dev %s parent %x:0 prio %d", dev, qdiscHandleIngress, priority)
			cmd = fmt.Sprintf("%s protocol %s chain %d handle %d flower", cmd, l3ProtoStr, 0, handle)
			cmd = fmt.Sprintf("%s ip_proto %s dst_ip %s dst_port %d", cmd, l4ProtoStr, dstIP.String(), dstPort)
			cmd = fmt.Sprintf("%s action mirred egress redirect dev %s", cmd, gateway)
			_, err = commandRun(cmd)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// interfaceFiltersDel deletes Linux TC filter for general interfaces(not including loopback and Antrea gateway)
func interfaceFiltersDel(ifIndex int, l4Protocol int, dstPort uint32, dstIPs []net.IP) error {
	if ifIndex == loopbackIfIndex {
		return nil
	}
	dev := getNameByIndex(ifIndex)

	for index, dstIP := range dstIPs {
		l3Proto := getL3Proto(dstIP)
		l3ProtoStr := getL3ProtoStr(l3Proto)
		priority := getPriority(l3Proto, ifIndex)
		handle := index<<24 | l3Proto&0xf<<20 | l4Protocol&0xf<<16 | int(dstPort)

		cmd := fmt.Sprintf("tc filter del dev %s parent %x:0 prio %d", dev, qdiscHandleIngress, priority)
		cmd = fmt.Sprintf("%s protocol %s chain %d handle %d flower", cmd, l3ProtoStr, 0, handle)
		_, err := commandRun(cmd)
		if err != nil {
			return err
		}
	}

	return nil
}

// gatewayBasicFiltersAdd creates basic Linux TC filters for gateway to distribute response NodePort traffic to target
// chain according to traffic source IP address and network layer protocol.
// ifIndex is target interface's index, and srcIPs are target interfaces' available NodePort IP addresses. These addresses
// can be IPv4 addresses or IPv6 addresses. For IPv4, response traffic matching the filter will be sent to a target chain.
// The target chain number is decided by IPv4/IPv6 and interface's index and an offset 0x100.
// For example, if protocol is IPv4((unix.IPPROTO_IP is 0x0) and interface is ethx(assumed that index is 0x10), then
// chain num is 0x0 << 8 + 0x100 + 0x10 = 0x110. If IPv6, then chain num is 0x3910(unix.IPPROTO_IPV6 is 0x29).
// Note that: the of offset is used to avoid chain 1. There is something strange when using chain 1.
// TODO: resolve the above issue.
func gatewayBasicFiltersAdd(ifIndex int, srcIPs []net.IP, gateway string) error {
	for index, srcIP := range srcIPs {
		l3Proto := getL3Proto(srcIP)
		l3ProtoStr := getL3ProtoStr(l3Proto)
		priorityNormal := getPriority(l3Proto, ifIndex)
		priorityHigh := getPriority(l3Proto, loopbackIfIndex)
		handle := 0x1<<24 | l3Proto<<16 | index<<8 | ifIndex
		gotoChainPrefix := l3Proto<<8 + 0x100

		exist, err := filterCheck(gateway, qdiscHandleIngress, priorityNormal, l3ProtoStr, 0, handle)
		if err != nil {
			return err
		}
		if !exist {
			cmd := fmt.Sprintf("tc filter add dev %s parent %x:0 prio %d", gateway, qdiscHandleIngress, priorityNormal)
			cmd = fmt.Sprintf("%s protocol %s handle %d flower src_ip %s action goto chain %d", cmd, l3ProtoStr, handle, srcIP.String(), gotoChainPrefix|ifIndex)
			if _, err = commandRun(cmd); err != nil {
				return err
			}
		}

		// Traffic which is from loopback should be also taken into consider. The feature of the traffic is that their
		// source and destination IP addresses are the same. The filter matching the traffic should have higher priority.
		exist, err = filterCheck(gateway, qdiscHandleIngress, priorityHigh, l3ProtoStr, 0, 1<<25|handle)
		if err != nil {
			return err
		}
		if !exist {
			if ifIndex != loopbackIfIndex {
				cmd := fmt.Sprintf("tc filter add dev %s parent %x:0 prio %d", gateway, qdiscHandleIngress, priorityHigh)
				cmd = fmt.Sprintf("%s protocol %s handle %d flower src_ip %s dst_ip %s", cmd, l3ProtoStr, 1<<25|handle, srcIP.String(), srcIP.String())
				cmd = fmt.Sprintf("%s action goto chain %d", cmd, gotoChainPrefix|loopbackIfIndex)
				if _, err = commandRun(cmd); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// gatewayFilterAdd creates specific filter for gateway to redirect response NodePort traffic to the interface where
// request traffic is from. This filter matches NodePort protocol/port.
// Note that: if the target interface is loopback, the source and destination MAC address should be rewritten to all-zero.
// For loopback, the traffic should be redirected to loopback's egress. For general interfaces, traffic should be redirected
// to its ingress.
func gatewayFilterAdd(dstIfIndex int, l3Proto, l4Proto int, srcPort uint32, gateway string) error {
	l3ProtoStr := getL3ProtoStr(l3Proto)
	l4ProtoStr := getL4ProtoStr(l4Proto)
	priority := getPriority(l3Proto, dstIfIndex)
	dev := getNameByIndex(dstIfIndex)
	handle := l4Proto<<16 | int(srcPort)
	chain := (l3Proto<<8 + 0x100) | dstIfIndex
	position := egress

	exist, err := filterCheck(gateway, qdiscHandleIngress, priority, l3ProtoStr, 0, handle)
	if err != nil {
		return err
	}
	if !exist {
		cmd := fmt.Sprintf("tc filter add dev %s parent %x:0 prio %d", gateway, qdiscHandleIngress, priority)
		cmd = fmt.Sprintf("%s chain %d handle %d protocol %s flower", cmd, chain, handle, l3ProtoStr)
		cmd = fmt.Sprintf("%s ip_proto %s src_port %d", cmd, l4ProtoStr, srcPort)
		if dstIfIndex == loopbackIfIndex {
			cmd = fmt.Sprintf("%s action skbmod set dmac %s set smac %s pipe", cmd, zeroMac, zeroMac)
			position = ingress
		}
		cmd = fmt.Sprintf("%s action mirred %s redirect dev %s", cmd, position, dev)
		_, err = commandRun(cmd)
		if err != nil {
			return err
		}
	}

	return nil
}

// gatewayFilterDel deletes specific filter by index for Antrea gateway.
func gatewayFilterDel(dstIfIndex int, l3Proto, l4Proto int, srcPort uint32, gateway string) error {
	priority := getPriority(l3Proto, dstIfIndex)
	handle := l4Proto<<16 | int(srcPort)
	chainPrefix := l3Proto<<8 + 0x100

	cmd := fmt.Sprintf("tc filter del dev %s parent %x:0 prio %d", gateway, qdiscHandleIngress, priority)
	cmd = fmt.Sprintf("%s chain %d handle %d flower", cmd, chainPrefix|dstIfIndex, handle)
	_, err := commandRun(cmd)
	if err != nil {
		return err
	}

	return nil
}

// filterCheck checks that whether specific filter exists.
func filterCheck(dev string, parent uint32, priority int, l3Proto string, chain, handle int) (bool, error) {
	// Use command to get filter
	cmd := fmt.Sprintf("tc filter get dev %s parent %x:0 prio %d", dev, parent, priority)
	cmd = fmt.Sprintf("%s protocol %s chain %d handle %d flower", cmd, l3Proto, chain, handle)
	output, err := commandRun(cmd)
	// If the filter doesn't exist, error is not nil and there might be three types output.
	if err != nil {
		if strings.Contains(output, filterNotFound1) ||
			strings.Contains(output, filterNotFound2) ||
			strings.Contains(output, filterNotFound3) {
			return false, nil
		} else {
			return false, err
		}
	}
	return true, nil
}
