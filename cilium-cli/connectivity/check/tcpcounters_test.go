// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// procNetSample is a trimmed cat of /proc/net/snmp followed by
// /proc/net/netstat, keeping the shape that matters: paired header and value
// lines, an IcmpMsg pair with no messages at all, and the wanted counters
// sitting at different offsets in each section.
const procNetSample = `Ip: Forwarding DefaultTTL InReceives InHdrErrors
Ip: 2 64 1291 0
IcmpMsg:
IcmpMsg:
Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors
Tcp: 1 200 120000 -1 148 3 0 1 2 1204 1198 7 0 5 0
Udp: InDatagrams NoPorts InErrors OutDatagrams
Udp: 96 0 0 96
TcpExt: SyncookiesSent TCPTimeouts TCPSynRetrans TCPLostRetransmit TCPOrigDataSent
TcpExt: 0 3 2 1 1100
IpExt: InNoRoutes InTruncatedPkts
IpExt: 0 0
`

func TestParseTCPCounters(t *testing.T) {
	counters := parseTCPCounters(procNetSample, tcpCounterNames)

	assert.Equal(t, tcpCounters{
		"Tcp:RetransSegs":          7,
		"Tcp:OutRsts":              5,
		"TcpExt:TCPTimeouts":       3,
		"TcpExt:TCPSynRetrans":     2,
		"TcpExt:TCPLostRetransmit": 1,
	}, counters)

	assert.Equal(t, "Tcp:RetransSegs=7 Tcp:OutRsts=5 TcpExt:TCPTimeouts=3"+
		" TcpExt:TCPSynRetrans=2 TcpExt:TCPLostRetransmit=1", counters.String())
}

func TestParseTCPCountersEmpty(t *testing.T) {
	// A truncated read must not invent counters, and an empty snapshot has to
	// stay readable in the log.
	counters := parseTCPCounters("Tcp: RtoAlgorithm RtoMin\n", tcpCounterNames)
	assert.Empty(t, counters)
	assert.Equal(t, "none", counters.String())
}

func TestTCPCountersSub(t *testing.T) {
	base := parseTCPCounters(procNetSample, tcpCounterNames)
	after := parseTCPCounters(procNetSample, tcpCounterNames)
	after["Tcp:RetransSegs"] += 2
	after["TcpExt:TCPSynRetrans"]++

	// Only the counters that moved during the failing action are non-zero, and
	// a counter missing from the baseline still yields its absolute value.
	assert.Equal(t, tcpCounters{
		"Tcp:RetransSegs":          2,
		"Tcp:OutRsts":              0,
		"TcpExt:TCPTimeouts":       0,
		"TcpExt:TCPSynRetrans":     1,
		"TcpExt:TCPLostRetransmit": 0,
	}, after.Sub(base))

	assert.Equal(t, tcpCounters{"Tcp:RetransSegs": 9}, tcpCounters{"Tcp:RetransSegs": 9}.Sub(nil))
}
