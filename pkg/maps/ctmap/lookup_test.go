// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/u8proto"
)

// TestEgressKey asserts that the key built for a flow renders as the entry that
// 'cilium bpf ct list' prints for it, which is the only check that the address
// and port fields are laid out the way the datapath stores them.
func TestEgressKey(t *testing.T) {
	for _, tc := range []struct {
		name   string
		proto  u8proto.U8proto
		client string
		server string
		want   string
	}{
		{
			name:   "udp v4",
			proto:  u8proto.UDP,
			client: "10.244.3.168:43852",
			server: "10.244.0.31:53",
			want:   "UDP OUT 10.244.3.168:43852 -> 10.244.0.31:53 ",
		},
		{
			name:   "tcp v4",
			proto:  u8proto.TCP,
			client: "10.244.3.168:43852",
			server: "10.244.0.31:53",
			want:   "TCP OUT 10.244.3.168:43852 -> 10.244.0.31:53 ",
		},
		{
			name:   "udp v6",
			proto:  u8proto.UDP,
			client: "[fd00::168]:43852",
			server: "[fd00::31]:53",
			want:   "UDP OUT fd00::168:43852 -> fd00::31:53 ",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := EgressKey(tc.proto,
				netip.MustParseAddrPort(tc.client),
				netip.MustParseAddrPort(tc.server))
			require.NoError(t, err)

			var sb strings.Builder
			require.True(t, key.ToHost().Dump(&sb, true))
			assert.Equal(t, tc.want, sb.String())
		})
	}
}

func TestPrivilegedLookupEgress(t *testing.T) {
	setupCTMap(t)

	m := newMap(MapNameAny4Global+"_test", mapTypeIPv4AnyGlobal)
	require.NoError(t, m.OpenOrCreate())
	t.Cleanup(func() { assert.NoError(t, m.Map.Unpin()) })
	ctMaps := &ctMaps{v4AnyMap: m}

	client := netip.MustParseAddrPort("10.244.3.168:43852")
	server := netip.MustParseAddrPort("10.244.0.31:53")

	entry, err := LookupEgress(ctMaps, u8proto.UDP, client, server)
	require.NoError(t, err)
	require.Nil(t, entry, "an absent entry is not an error")

	key, err := EgressKey(u8proto.UDP, client, server)
	require.NoError(t, err)
	require.NoError(t, m.Map.Update(key, &CtEntry{Flags: ProxyRedirect, Packets: 8}))

	entry, err = LookupEgress(ctMaps, u8proto.UDP, client, server)
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.NotZero(t, entry.Flags&ProxyRedirect)
	assert.Equal(t, uint64(8), entry.Packets)

	// The entry is not in the TCP map, which is not even in use here.
	_, err = LookupEgress(ctMaps, u8proto.TCP, client, server)
	require.Error(t, err)
}

func TestEgressKeyFamilyMismatch(t *testing.T) {
	_, err := EgressKey(u8proto.UDP,
		netip.MustParseAddrPort("10.244.3.168:43852"),
		netip.MustParseAddrPort("[fd00::31]:53"))
	require.Error(t, err)
}
