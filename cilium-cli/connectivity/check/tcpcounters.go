// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// tcpCountersCmd reads the TCP counters of the network namespace it runs in.
var tcpCountersCmd = []string{"cat", "/proc/net/snmp", "/proc/net/netstat"}

// tcpCounterNames are the counters that separate a segment that was dropped and
// retransmitted from a client that was merely off-CPU, keyed as they appear in
// the two files read by tcpCountersCmd.
var tcpCounterNames = []string{
	"Tcp:RetransSegs",
	"Tcp:OutRsts",
	"TcpExt:TCPTimeouts",
	"TcpExt:TCPSynRetrans",
	"TcpExt:TCPLostRetransmit",
}

// tcpCounters is a snapshot of tcpCounterNames taken in a pod network namespace.
type tcpCounters map[string]int64

// Sub returns c minus base, so a caller can attribute an increase to the window
// between the two snapshots.
func (c tcpCounters) Sub(base tcpCounters) tcpCounters {
	delta := make(tcpCounters, len(c))
	for name, value := range c {
		delta[name] = value - base[name]
	}
	return delta
}

// String renders the counters in tcpCounterNames order so that two snapshots
// can be compared by eye in the test log.
func (c tcpCounters) String() string {
	var sb strings.Builder
	for _, name := range tcpCounterNames {
		value, ok := c[name]
		if !ok {
			continue
		}
		if sb.Len() > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "%s=%d", name, value)
	}
	if sb.Len() == 0 {
		return "none"
	}
	return sb.String()
}

// parseTCPCounters reads the paired "Prefix: names" and "Prefix: values" lines
// of /proc/net/snmp and /proc/net/netstat, keeping only the wanted counters.
func parseTCPCounters(out string, want []string) tcpCounters {
	keep := make(map[string]struct{}, len(want))
	for _, name := range want {
		keep[name] = struct{}{}
	}

	counters := make(tcpCounters, len(want))
	headers := make(map[string][]string)
	for line := range strings.SplitSeq(out, "\n") {
		prefix, rest, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		names, seen := headers[prefix]
		if !seen {
			headers[prefix] = fields
			continue
		}
		// The values line closes the pair, so a repeated prefix starts a new one.
		delete(headers, prefix)
		for i, name := range names {
			if i >= len(fields) {
				break
			}
			key := prefix + ":" + name
			if _, ok := keep[key]; !ok {
				continue
			}
			if value, err := strconv.ParseInt(fields[i], 10, 64); err == nil {
				counters[key] = value
			}
		}
	}
	return counters
}

// collectTCPCounters snapshots the TCP counters of a pod's network namespace.
func (ct *ConnectivityTest) collectTCPCounters(ctx context.Context, pod Pod) (tcpCounters, error) {
	out, err := ct.execInPodWithTransportRetry(ctx, pod.K8sClient, pod.Pod.Namespace,
		pod.Pod.Name, pod.Pod.Spec.Containers[0].Name, tcpCountersCmd)
	if err != nil {
		return nil, err
	}
	return parseTCPCounters(out.String(), tcpCounterNames), nil
}

// collectTCPCountersBaseline records the counters of every client pod once the
// deployments are ready, which is the reference an on-failure snapshot needs to
// mean anything.
func (ct *ConnectivityTest) collectTCPCountersBaseline(ctx context.Context) {
	for _, pod := range ct.clientPods {
		counters, err := ct.collectTCPCounters(ctx, pod)
		if err != nil {
			ct.Warnf("Unable to read TCP counters of pod %s: %s", pod.Name(), err)
			continue
		}
		ct.tcpCountersBaseline[pod.Name()] = counters
		ct.Debugf("TCP counters baseline for pod %s: %s", pod.Name(), counters)
	}
}
