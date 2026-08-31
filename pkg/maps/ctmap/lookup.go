// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/u8proto"
)

// EgressKey returns the global CT map key of the entry that the datapath
// creates for the egress direction of the flow client -> server. Address and
// port fields are laid out as they appear in the reply, see tuple.TupleKey4.
func EgressKey(proto u8proto.U8proto, client, server netip.AddrPort) (CtKey, error) {
	clientAddr, serverAddr := client.Addr().Unmap(), server.Addr().Unmap()
	if clientAddr.Is4() != serverAddr.Is4() {
		return nil, fmt.Errorf("address family mismatch between %s and %s", client, server)
	}

	if clientAddr.Is4() {
		key := &CtKey4Global{tuple.TupleKey4Global{TupleKey4: tuple.TupleKey4{
			SourcePort: client.Port(),
			DestPort:   server.Port(),
			NextHeader: proto,
			Flags:      tuple.TUPLE_F_OUT,
		}}}
		key.SourceAddr.FromAddr(serverAddr)
		key.DestAddr.FromAddr(clientAddr)
		return key.ToNetwork(), nil
	}

	key := &CtKey6Global{tuple.TupleKey6Global{TupleKey6: tuple.TupleKey6{
		SourcePort: client.Port(),
		DestPort:   server.Port(),
		NextHeader: proto,
		Flags:      tuple.TUPLE_F_OUT,
	}}}
	key.SourceAddr.FromAddr(serverAddr)
	key.DestAddr.FromAddr(clientAddr)
	return key.ToNetwork(), nil
}

// LookupEgress returns the entry that the datapath created in the global
// conntrack map for the egress direction of the flow client -> server, or a nil
// entry and a nil error when the map holds no such entry.
func LookupEgress(maps CTMaps, proto u8proto.U8proto, client, server netip.AddrPort) (*CtEntry, error) {
	key, err := EgressKey(proto, client, server)
	if err != nil {
		return nil, err
	}

	// Map selection mirrors get_ct_map4() and get_ct_map6(): everything that is
	// not TCP is tracked in the "any" maps.
	cfg := MapConfig{IPv6: !client.Addr().Unmap().Is4(), TCP: proto == u8proto.TCP}
	var ctMap *Map
	for _, m := range maps.ActiveMaps() {
		if m.mapType == cfg.mapType() {
			ctMap = m
			break
		}
	}
	if ctMap == nil {
		return nil, fmt.Errorf("%s is not in use", cfg.mapType())
	}
	if !ctMap.IsOpen() {
		return nil, fmt.Errorf("%s is not open", ctMap.Name())
	}

	value, err := ctMap.Lookup(key)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	entry, ok := value.(*CtEntry)
	if !ok {
		return nil, fmt.Errorf("unexpected value type %T in %s", value, ctMap.Name())
	}
	return entry, nil
}
