// nolint
package routing

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/asciimoth/gonnect/sockowner"
	"github.com/asciimoth/gonnect/sysnet"
	sysnetdebug "github.com/asciimoth/gonnect/sysnet/debug"
)

func TestBytecodeRouterCfgRoutesByBytecode(t *testing.T) {
	addr6 := netip.MustParseAddr("2001:db8::1")
	subnet6 := netip.MustParsePrefix("2001:db8:abcd::/48")
	cfg, err := NewBytecodeRouterCfg(BytecodeRules{
		Strings:     []string{"example.com"},
		Regexps:     []*regexp.Regexp{regexp.MustCompile(`^api\.`)},
		IPv4Addrs:   []uint32{ip4(192, 0, 2, 10)},
		IPv4Subnets: []IPv4Subnet{{Addr: ip4(10, 0, 0, 0), Bits: 8}},
		IPv6Addrs:   []netip.Addr{addr6},
		IPv6Subnets: []netip.Prefix{subnet6},
		DialTCP: append(
			append(param16(OP_ADDR_S, 0), OP_SLOT, 2),
			append(param16(OP_ADDR4, 0), OP_SLOT, 3)...,
		),
		ListenTCP: append(param16(OP_LPORT, 80), OP_SLOT, 4),
		DialUDP: append(
			append([]byte{OP_UDP}, param16(OP_PORT, 53)...),
			OP_AND, OP_SLOT, 5,
		),
		RouteUDP: append(
			append(param16(OP_LSNET4, 0), param16(OP_ADDR6, 0)...),
			OP_OR, OP_SLOT, 6,
		),
		Lookup: append(
			append([]byte{OP_FQDN}, param16(OP_ADDR_RE, 0)...),
			OP_AND, OP_SLOT, 7,
		),
	})
	if err != nil {
		t.Fatalf("NewBytecodeRouterCfg() error = %v", err)
	}

	if got := cfg.DialTCP("tcp", "", "example.com:443"); got != 2 {
		t.Fatalf("DialTCP string route = %d, want 2", got)
	}
	if got := cfg.DialTCP("tcp", "", "192.0.2.10:443"); got != 3 {
		t.Fatalf("DialTCP IPv4 route = %d, want 3", got)
	}
	if got := cfg.DialTCP("tcp", "", "other.example:443"); got != 0 {
		t.Fatalf("DialTCP default route = %d, want 0", got)
	}
	if got := cfg.ListenTCP("tcp", "127.0.0.1:http"); got != 4 {
		t.Fatalf("ListenTCP service port route = %d, want 4", got)
	}
	if got := cfg.DialUDP("udp", "", "8.8.8.8:dns"); got != 5 {
		t.Fatalf("DialUDP service port route = %d, want 5", got)
	}
	if got := cfg.RouteUDP(
		"udp",
		&net.UDPAddr{IP: net.IPv4(10, 1, 2, 3), Port: 1234},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 53},
	); got != 6 {
		t.Fatalf("RouteUDP local subnet route = %d, want 6", got)
	}
	if got := cfg.RouteUDP(
		"udp6",
		&net.UDPAddr{IP: net.ParseIP("2001:db8:abcd::2"), Port: 1234},
		&net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 53},
	); got != 6 {
		t.Fatalf("RouteUDP IPv6 address route = %d, want 6", got)
	}
	if got := cfg.Lookup("ip", "api.example.com"); got != 7 {
		t.Fatalf("Lookup route = %d, want 7", got)
	}
	if got := cfg.Lookup("ip", "2001:db8::1"); got != 0 {
		t.Fatalf("Lookup IP route = %d, want 0", got)
	}
}

func TestBytecodeRouterCfgMethodOps(t *testing.T) {
	cfg, err := NewBytecodeRouterCfg(BytecodeRules{
		DialTCP: []byte{
			OP_LISTEN, OP_SLOT, 9,
			OP_LOOKUP, OP_SLOT, 10,
			OP_DIAL, OP_SLOT, 2,
		},
		ListenTCP: []byte{
			OP_DIAL, OP_SLOT, 9,
			OP_LOOKUP, OP_SLOT, 10,
			OP_LISTEN, OP_SLOT, 3,
		},
		DialUDP: []byte{
			OP_LISTEN, OP_SLOT, 9,
			OP_LOOKUP, OP_SLOT, 10,
			OP_DIAL, OP_SLOT, 4,
		},
		RouteUDP: []byte{
			OP_LISTEN, OP_SLOT, 9,
			OP_LOOKUP, OP_SLOT, 10,
			OP_DIAL, OP_SLOT, 5,
		},
		Lookup: []byte{
			OP_DIAL, OP_SLOT, 9,
			OP_LISTEN, OP_SLOT, 10,
			OP_LOOKUP, OP_SLOT, 6,
		},
	})
	if err != nil {
		t.Fatalf("NewBytecodeRouterCfg() error = %v", err)
	}

	if got := cfg.DialTCP("tcp", "", "example.com:443"); got != 2 {
		t.Fatalf("DialTCP method route = %d, want 2", got)
	}
	if got := cfg.ListenTCP("tcp", "127.0.0.1:80"); got != 3 {
		t.Fatalf("ListenTCP method route = %d, want 3", got)
	}
	if got := cfg.DialUDP("udp", "", "192.0.2.1:53"); got != 4 {
		t.Fatalf("DialUDP method route = %d, want 4", got)
	}
	if got := cfg.RouteUDP(
		"udp",
		&net.UDPAddr{IP: net.IPv4(10, 1, 2, 3), Port: 1234},
		&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53},
	); got != 5 {
		t.Fatalf("RouteUDP method route = %d, want 5", got)
	}
	if got := cfg.Lookup("ip", "example.com"); got != 6 {
		t.Fatalf("Lookup method route = %d, want 6", got)
	}
}

func TestBytecodeRouterCfgNetworkFamily(t *testing.T) {
	cfg, err := NewBytecodeRouterCfg(BytecodeRules{
		DialTCP: append(
			append([]byte{OP_NET4, OP_SLOT, 2, OP_NET6, OP_SLOT, 3}, OP_TRUE),
			OP_SLOT, 1,
		),
	})
	if err != nil {
		t.Fatalf("NewBytecodeRouterCfg() error = %v", err)
	}

	tests := []struct {
		network string
		raddr   string
		want    int
	}{
		{network: "tcp4", raddr: "example.com:80", want: 2},
		{network: "tcp6", raddr: "example.com:80", want: 3},
		{network: "tcp", raddr: "192.0.2.1:80", want: 2},
		{network: "tcp", raddr: "[2001:db8::1]:80", want: 3},
		{network: "tcp", raddr: "example.com:80", want: 1},
	}
	for _, tt := range tests {
		if got := cfg.DialTCP(tt.network, "", tt.raddr); got != tt.want {
			t.Fatalf(
				"DialTCP(%q, %q) = %d, want %d",
				tt.network,
				tt.raddr,
				got,
				tt.want,
			)
		}
	}
}

func TestBytecodeRouterCfgPortMatchesBareService(t *testing.T) {
	cfg, err := NewBytecodeRouterCfg(BytecodeRules{
		Lookup: append(param16(OP_PORT, 80), OP_SLOT, 2),
	})
	if err != nil {
		t.Fatalf("NewBytecodeRouterCfg() error = %v", err)
	}

	if got := cfg.Lookup("tcp", "http"); got != 2 {
		t.Fatalf("Lookup bare service route = %d, want 2", got)
	}
	if got := cfg.Lookup("tcp", "80"); got != 2 {
		t.Fatalf("Lookup bare numeric port route = %d, want 2", got)
	}
	if got := cfg.Lookup("udp", "ntp"); got != 0 {
		t.Fatalf("Lookup wrong service route = %d, want 0", got)
	}
}

func TestBytecodeRouterCfgIPChecksOnWrongAddressTypeAreFalse(t *testing.T) {
	cfg, err := NewBytecodeRouterCfg(BytecodeRules{
		IPv4Addrs:   []uint32{0},
		IPv4Subnets: []IPv4Subnet{{Addr: 0, Bits: 0}},
		DialTCP: append(
			append(param16(OP_ADDR4, 0), OP_SLOT, 2),
			append(param16(OP_SNET4, 0), OP_SLOT, 3)...,
		),
	})
	if err != nil {
		t.Fatalf("NewBytecodeRouterCfg() error = %v", err)
	}

	if got := cfg.DialTCP("tcp", "", "example.com:80"); got != 0 {
		t.Fatalf("FQDN IPv4 checks route = %d, want 0", got)
	}
	if got := cfg.DialTCP("tcp", "", "[2001:db8::1]:80"); got != 0 {
		t.Fatalf("IPv6 IPv4 checks route = %d, want 0", got)
	}
	if got := cfg.DialTCP("tcp", "", "192.0.2.1:80"); got != 3 {
		t.Fatalf("IPv4 /0 subnet route = %d, want 3", got)
	}
}

func TestBytecodeRouterCfgConstructionCopiesRules(t *testing.T) {
	code := append(param16(OP_ADDR_S, 0), OP_SLOT, 2)
	rules := BytecodeRules{
		Strings: []string{"example.com"},
		DialTCP: code,
	}
	cfg, err := NewBytecodeRouterCfg(rules)
	if err != nil {
		t.Fatalf("NewBytecodeRouterCfg() error = %v", err)
	}
	rules.Strings[0] = "changed.example"
	code[0] = OP_TRUE

	if got := cfg.DialTCP("tcp", "", "example.com:80"); got != 2 {
		t.Fatalf("route after mutating source rules = %d, want 2", got)
	}
}

func TestBytecodeRouterCfgReportsMentionedSlots(t *testing.T) {
	cfg, err := NewBytecodeRouterCfg(BytecodeRules{
		DialTCP: []byte{
			OP_TRUE, OP_SLOT, 2,
			OP_TRUE, OP_SLOT, 0,
			OP_TRUE, OP_SLOT, 2,
		},
		ListenTCP: []byte{OP_TRUE, OP_SLOT, 7},
		DialUDP:   []byte{OP_TRUE, OP_DROP},
		RouteUDP:  []byte{OP_TRUE, OP_SLOT, 1},
		Lookup:    []byte{OP_TRUE, OP_SLOT, 16},
	})
	if err != nil {
		t.Fatalf("NewBytecodeRouterCfg() error = %v", err)
	}
	got := cfg.MentionedSlots()
	want := []int{1, 2, 7, 16}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MentionedSlots() = %v, want %v", got, want)
	}

	got[0] = 99
	if got := cfg.MentionedSlots(); !reflect.DeepEqual(got, want) {
		t.Fatalf("MentionedSlots() after caller mutation = %v, want %v", got, want)
	}
}

func TestBytecodeRouterCfgValidation(t *testing.T) {
	validPrefix := netip.MustParsePrefix("2001:db8::/32")
	tests := []struct {
		name  string
		rules BytecodeRules
		want  string
	}{
		{
			name:  "unknown opcode",
			rules: BytecodeRules{DialTCP: []byte{255}},
			want:  "unknown opcode",
		},
		{
			name: "split opcode",
			rules: BytecodeRules{
				DialTCP: param16(OP_RULE, 0),
			},
			want: "not valid for RouterCfg",
		},
		{
			name:  "missing uint8 param",
			rules: BytecodeRules{DialTCP: []byte{OP_TRUE, OP_SLOT}},
			want:  "missing uint8 parameter",
		},
		{
			name:  "missing uint16 param",
			rules: BytecodeRules{DialTCP: []byte{OP_ADDR_S, 0}},
			want:  "missing uint16 parameter",
		},
		{
			name:  "string index",
			rules: BytecodeRules{DialTCP: param16(OP_ADDR_S, 0)},
			want:  "string index 0 out of range 0",
		},
		{
			name: "regexp nil",
			rules: BytecodeRules{
				Regexps: []*regexp.Regexp{nil},
			},
			want: "regexp 0 is nil",
		},
		{
			name: "regexp index",
			rules: BytecodeRules{
				DialTCP: param16(OP_ADDR_RE, 0),
			},
			want: "regexp index 0 out of range 0",
		},
		{
			name: "slot range",
			rules: BytecodeRules{
				DialTCP: []byte{OP_TRUE, OP_SLOT, 17},
			},
			want: "slot 17 out of range",
		},
		{
			name: "stack underflow",
			rules: BytecodeRules{
				DialTCP: []byte{OP_AND},
			},
			want: "stack underflow",
		},
		{
			name: "lookup laddr op",
			rules: BytecodeRules{
				Lookup: []byte{OP_LFQDN},
			},
			want: "local-address opcode",
		},
		{
			name: "invalid IPv4 subnet",
			rules: BytecodeRules{
				IPv4Subnets: []IPv4Subnet{{Bits: 33}},
			},
			want: "prefix length 33",
		},
		{
			name: "invalid IPv6 address",
			rules: BytecodeRules{
				IPv6Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")},
			},
			want: "IPv6 address 0",
		},
		{
			name: "invalid IPv6 subnet",
			rules: BytecodeRules{
				IPv6Subnets: []netip.Prefix{
					netip.MustParsePrefix("192.0.2.0/24"),
				},
			},
			want: "IPv6 subnet 0",
		},
		{
			name: "valid IPv6 subnet referenced",
			rules: BytecodeRules{
				IPv6Subnets: []netip.Prefix{validPrefix},
				DialTCP:     append(param16(OP_SNET6, 0), OP_SLOT, 2),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewBytecodeRouterCfg(tt.rules)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("NewBytecodeRouterCfg() error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("NewBytecodeRouterCfg() succeeded, want error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf(
					"NewBytecodeRouterCfg() error = %q, want substring %q",
					err,
					tt.want,
				)
			}
		})
	}
}

func TestBytecodeSplitRouterRoutesPackets(t *testing.T) {
	cfg, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System:    &sysnetdebug.System{},
		IPv4Addrs: []uint32{ip4(192, 0, 2, 2)},
		Route: append(
			append(
				append(
					append([]byte{OP_NET4, OP_TCP}, OP_AND),
					param16(OP_ADDR4, 0)...,
				),
				OP_AND,
			),
			append(param16(OP_PORT, 443), OP_AND, OP_SLOT, 4)...,
		),
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}

	pkt := ipv4TCPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{192, 0, 2, 2},
		12345,
		443,
	)
	buf := append([]byte{0xaa, 0xbb, 0xcc}, pkt...)
	cfg.Lock()
	got := cfg.Route(buf, 3, false)
	cfg.Unlock()
	if got != 4 {
		t.Fatalf("Route() = %d, want 4", got)
	}
	if got := cfg.Route(buf[:3], 3, false); got != 0 {
		t.Fatalf("Route(malformed) = %d, want 0", got)
	}
}

func TestBytecodeSplitRouterMatcherCaching(t *testing.T) {
	rule := sysnet.Rule{Type: "test", Rule: "cached rule"}
	var matchCalls int
	system := &sysnetdebug.System{
		RuleMatcher: func(got sysnet.Rule, flow sockowner.FlowTuple) (bool, error) {
			matchCalls++
			return got == rule &&
				flow.Proto == "tcp" &&
				flow.LocalPort == 1 &&
				flow.RemotePort == 2, nil
		},
	}
	cfg, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System: system,
		Rules:  []sysnet.Rule{rule},
		Route: append(
			append(
				append(
					param16(OP_RULE, 0),
					param16(OP_RULE, 0)...,
				),
				OP_AND,
			),
			OP_SLOT, 8,
		),
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}

	if got := cfg.Route(
		ipv4TCPPacket([4]byte{10, 0, 0, 1}, [4]byte{192, 0, 2, 2}, 1, 2),
		0,
		true,
	); got != 8 {
		t.Fatalf("Route() = %d, want 8", got)
	}
	if matchCalls != 1 {
		t.Fatalf("Match calls = %d, want 1", matchCalls)
	}
}

func TestBytecodeSplitRouterShortCircuitsRuleGuards(t *testing.T) {
	rule := sysnet.Rule{Type: "test", Rule: "guarded rule"}
	pkt := ipv4TCPPacket(
		[4]byte{10, 0, 0, 1},
		[4]byte{192, 0, 2, 2},
		1,
		2,
	)
	tests := []struct {
		name string
		code []byte
		want int
	}{
		{
			name: "false and guard",
			code: slotWhen(andAll(
				[]byte{OP_TCP},
				param16(OP_ADDR4, 0),
				param16(OP_RULE, 0),
			), 8),
			want: 0,
		},
		{
			name: "true or guard",
			code: slotWhen(orOp(
				[]byte{OP_TCP},
				param16(OP_RULE, 0),
			), 8),
			want: 8,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var matchCalls int
			cfg, err := NewBytecodeSplitRouter(SplitBytecodeRules{
				System: &sysnetdebug.System{
					RuleMatcher: func(sysnet.Rule, sockowner.FlowTuple) (bool, error) {
						matchCalls++
						return true, nil
					},
				},
				Rules:         []sysnet.Rule{rule},
				IPv4Addrs:     []uint32{ip4(203, 0, 113, 1)},
				RuleCacheTTL:  -1,
				RouteCacheTTL: -1,
				Route:         tt.code,
			})
			if err != nil {
				t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
			}
			if got := cfg.Route(pkt, 0, true); got != tt.want {
				t.Fatalf("Route() = %d, want %d", got, tt.want)
			}
			if matchCalls != 0 {
				t.Fatalf("Match calls = %d, want 0", matchCalls)
			}
		})
	}
}

func TestBytecodeSplitRouterMatcherCachesRepeatedFlow(t *testing.T) {
	rule := sysnet.Rule{Type: "test", Rule: "cached flow"}
	var matchCalls int
	system := &sysnetdebug.System{
		RuleMatcher: func(got sysnet.Rule, flow sockowner.FlowTuple) (bool, error) {
			matchCalls++
			return got == rule &&
				flow.Proto == "tcp" &&
				flow.LocalPort == 1 &&
				flow.RemotePort == 2, nil
		},
	}
	cfg, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System:       system,
		Rules:        []sysnet.Rule{rule},
		RuleCacheTTL: time.Minute,
		Route:        append(param16(OP_RULE, 0), OP_SLOT, 8),
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}

	pkt := ipv4TCPPacket([4]byte{10, 0, 0, 1}, [4]byte{192, 0, 2, 2}, 1, 2)
	for i := 0; i < 2; i++ {
		if got := cfg.Route(pkt, 0, true); got != 8 {
			t.Fatalf("Route(%d) = %d, want 8", i, got)
		}
	}
	if matchCalls != 1 {
		t.Fatalf("Match calls = %d, want 1", matchCalls)
	}
}

func TestBytecodeSplitRouterMatcherCachesFalseResults(t *testing.T) {
	rule := sysnet.Rule{Type: "test", Rule: "cached miss"}
	var matchCalls int
	system := &sysnetdebug.System{
		RuleMatcher: func(sysnet.Rule, sockowner.FlowTuple) (bool, error) {
			matchCalls++
			return false, nil
		},
	}
	cfg, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System:        system,
		Rules:         []sysnet.Rule{rule},
		RuleCacheTTL:  time.Minute,
		RouteCacheTTL: -1,
		Route:         append(param16(OP_RULE, 0), OP_SLOT, 8),
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}

	pkt := ipv4TCPPacket([4]byte{10, 0, 0, 1}, [4]byte{192, 0, 2, 2}, 1, 2)
	for i := 0; i < 2; i++ {
		if got := cfg.Route(pkt, 0, true); got != 0 {
			t.Fatalf("Route(%d) = %d, want 0", i, got)
		}
	}
	if matchCalls != 1 {
		t.Fatalf("Match calls = %d, want 1", matchCalls)
	}
}

func TestBytecodeSplitRouterMatcherCacheDoesNotCacheErrors(t *testing.T) {
	rule := sysnet.Rule{Type: "test", Rule: "flaky matcher"}
	var matchCalls int
	system := &sysnetdebug.System{
		RuleMatcher: func(sysnet.Rule, sockowner.FlowTuple) (bool, error) {
			matchCalls++
			if matchCalls == 1 {
				return false, errors.New("temporary matcher failure")
			}
			return true, nil
		},
	}
	cfg, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System:        system,
		Rules:         []sysnet.Rule{rule},
		RuleCacheTTL:  time.Minute,
		RouteCacheTTL: -1,
		Route:         append(param16(OP_RULE, 0), OP_SLOT, 8),
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}

	pkt := ipv4TCPPacket([4]byte{10, 0, 0, 1}, [4]byte{192, 0, 2, 2}, 1, 2)
	if got := cfg.Route(pkt, 0, true); got != 0 {
		t.Fatalf("Route(first) = %d, want 0", got)
	}
	if got := cfg.Route(pkt, 0, true); got != 8 {
		t.Fatalf("Route(second) = %d, want 8", got)
	}
	if got := cfg.Route(pkt, 0, true); got != 8 {
		t.Fatalf("Route(third) = %d, want 8", got)
	}
	if matchCalls != 2 {
		t.Fatalf("Match calls = %d, want 2", matchCalls)
	}
}

func TestBytecodeSplitRouterMatcherCacheKeyIncludesProtocol(t *testing.T) {
	rule := sysnet.Rule{Type: "test", Rule: "protocol scoped"}
	var matchCalls int
	system := &sysnetdebug.System{
		RuleMatcher: func(got sysnet.Rule, flow sockowner.FlowTuple) (bool, error) {
			matchCalls++
			return got == rule && flow.Proto == "tcp", nil
		},
	}
	cfg, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System:        system,
		Rules:         []sysnet.Rule{rule},
		RuleCacheTTL:  time.Minute,
		RouteCacheTTL: -1,
		Route:         append(param16(OP_RULE, 0), OP_SLOT, 8),
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}

	src := [4]byte{10, 0, 0, 1}
	dst := [4]byte{192, 0, 2, 2}
	tcp := ipv4TCPPacket(src, dst, 1, 2)
	udp := ipv4UDPPacket(src, dst, 1, 2)
	if got := cfg.Route(tcp, 0, true); got != 8 {
		t.Fatalf("Route(tcp first) = %d, want 8", got)
	}
	if got := cfg.Route(udp, 0, true); got != 0 {
		t.Fatalf("Route(udp) = %d, want 0", got)
	}
	if got := cfg.Route(tcp, 0, true); got != 8 {
		t.Fatalf("Route(tcp second) = %d, want 8", got)
	}
	if matchCalls != 2 {
		t.Fatalf("Match calls = %d, want 2", matchCalls)
	}
}

func TestBytecodeSplitRouterDedupesRuleIndexesAboveMask(t *testing.T) {
	target := sysnet.Rule{Type: "test", Rule: "rule 64"}
	rules := make([]sysnet.Rule, 65)
	rules[64] = target
	var matchCalls int
	system := &sysnetdebug.System{
		RuleMatcher: func(got sysnet.Rule, flow sockowner.FlowTuple) (bool, error) {
			matchCalls++
			return got == target &&
				flow.Proto == "tcp" &&
				flow.LocalPort == 1 &&
				flow.RemotePort == 2, nil
		},
	}
	cfg, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System:        system,
		Rules:         rules,
		RuleCacheTTL:  -1,
		RouteCacheTTL: -1,
		Route: slotWhen(andAll(
			param16(OP_RULE, 64),
			param16(OP_RULE, 64),
		), 8),
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}

	pkt := ipv4TCPPacket([4]byte{10, 0, 0, 1}, [4]byte{192, 0, 2, 2}, 1, 2)
	if got := cfg.Route(pkt, 0, true); got != 8 {
		t.Fatalf("Route() = %d, want 8", got)
	}
	if matchCalls != 1 {
		t.Fatalf("Match calls = %d, want 1", matchCalls)
	}
}

func TestBytecodeSplitRouterMatcherCacheExpires(t *testing.T) {
	rule := sysnet.Rule{Type: "test", Rule: "short cache"}
	var matchCalls int
	system := &sysnetdebug.System{
		RuleMatcher: func(got sysnet.Rule, flow sockowner.FlowTuple) (bool, error) {
			matchCalls++
			return got == rule &&
				flow.Proto == "tcp" &&
				flow.LocalPort == 1 &&
				flow.RemotePort == 2, nil
		},
	}
	cfg, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System:       system,
		Rules:        []sysnet.Rule{rule},
		RuleCacheTTL: time.Nanosecond,
		Route:        append(param16(OP_RULE, 0), OP_SLOT, 8),
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}

	pkt := ipv4TCPPacket([4]byte{10, 0, 0, 1}, [4]byte{192, 0, 2, 2}, 1, 2)
	if got := cfg.Route(pkt, 0, true); got != 8 {
		t.Fatalf("Route(first) = %d, want 8", got)
	}
	time.Sleep(time.Millisecond)
	if got := cfg.Route(pkt, 0, true); got != 8 {
		t.Fatalf("Route(second) = %d, want 8", got)
	}
	if matchCalls != 2 {
		t.Fatalf("Match calls = %d, want 2", matchCalls)
	}
}

func TestBytecodeSplitRouterMatcherCacheKeyIncludesFlow(t *testing.T) {
	rule := sysnet.Rule{Type: "test", Rule: "per flow"}
	var matchCalls int
	system := &sysnetdebug.System{
		RuleMatcher: func(got sysnet.Rule, flow sockowner.FlowTuple) (bool, error) {
			matchCalls++
			return got == rule &&
				flow.Proto == "tcp" &&
				flow.RemotePort == 2, nil
		},
	}
	cfg, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System:       system,
		Rules:        []sysnet.Rule{rule},
		RuleCacheTTL: time.Minute,
		Route:        append(param16(OP_RULE, 0), OP_SLOT, 8),
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}

	pkt1 := ipv4TCPPacket([4]byte{10, 0, 0, 1}, [4]byte{192, 0, 2, 2}, 1, 2)
	pkt2 := ipv4TCPPacket([4]byte{10, 0, 0, 1}, [4]byte{192, 0, 2, 2}, 3, 2)
	if got := cfg.Route(pkt1, 0, true); got != 8 {
		t.Fatalf("Route(pkt1) = %d, want 8", got)
	}
	if got := cfg.Route(pkt2, 0, true); got != 8 {
		t.Fatalf("Route(pkt2) = %d, want 8", got)
	}
	if matchCalls != 2 {
		t.Fatalf("Match calls = %d, want 2", matchCalls)
	}
}

func TestBytecodeSplitRouterRouteCacheCachesWholeEvaluation(t *testing.T) {
	rule := sysnet.Rule{Type: "test", Rule: "cached route"}
	var matchCalls int
	system := &sysnetdebug.System{
		RuleMatcher: func(got sysnet.Rule, flow sockowner.FlowTuple) (bool, error) {
			matchCalls++
			return got == rule &&
				flow.Proto == "tcp" &&
				flow.LocalPort == 1 &&
				flow.RemotePort == 2, nil
		},
	}
	cfg, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System:        system,
		Rules:         []sysnet.Rule{rule},
		RuleCacheTTL:  -1,
		RouteCacheTTL: time.Minute,
		Route:         append(param16(OP_RULE, 0), OP_SLOT, 8),
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}

	pkt := ipv4TCPPacket([4]byte{10, 0, 0, 1}, [4]byte{192, 0, 2, 2}, 1, 2)
	for i := 0; i < 2; i++ {
		if got := cfg.Route(pkt, 0, true); got != 8 {
			t.Fatalf("Route(%d) = %d, want 8", i, got)
		}
	}
	if matchCalls != 1 {
		t.Fatalf("Match calls = %d, want 1", matchCalls)
	}
}

func TestBytecodeSplitRouterRouteCacheFollowsRuleCacheDisable(t *testing.T) {
	rule := sysnet.Rule{Type: "test", Rule: "uncached route"}
	var matchCalls int
	system := &sysnetdebug.System{
		RuleMatcher: func(sysnet.Rule, sockowner.FlowTuple) (bool, error) {
			matchCalls++
			return true, nil
		},
	}
	cfg, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System:       system,
		Rules:        []sysnet.Rule{rule},
		RuleCacheTTL: -1,
		Route:        append(param16(OP_RULE, 0), OP_SLOT, 8),
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}

	pkt := ipv4TCPPacket([4]byte{10, 0, 0, 1}, [4]byte{192, 0, 2, 2}, 1, 2)
	for i := 0; i < 2; i++ {
		if got := cfg.Route(pkt, 0, true); got != 8 {
			t.Fatalf("Route(%d) = %d, want 8", i, got)
		}
	}
	if matchCalls != 2 {
		t.Fatalf("Match calls = %d, want 2", matchCalls)
	}
}

func TestBytecodeSplitRouterRouteCacheDoesNotCacheMatcherErrors(t *testing.T) {
	rule := sysnet.Rule{Type: "test", Rule: "flaky route"}
	var matchCalls int
	system := &sysnetdebug.System{
		RuleMatcher: func(sysnet.Rule, sockowner.FlowTuple) (bool, error) {
			matchCalls++
			if matchCalls == 1 {
				return false, errors.New("temporary matcher failure")
			}
			return true, nil
		},
	}
	cfg, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System:        system,
		Rules:         []sysnet.Rule{rule},
		RuleCacheTTL:  -1,
		RouteCacheTTL: time.Minute,
		Route:         append(param16(OP_RULE, 0), OP_SLOT, 8),
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}

	pkt := ipv4TCPPacket([4]byte{10, 0, 0, 1}, [4]byte{192, 0, 2, 2}, 1, 2)
	if got := cfg.Route(pkt, 0, true); got != 0 {
		t.Fatalf("Route(first) = %d, want 0", got)
	}
	if got := cfg.Route(pkt, 0, true); got != 8 {
		t.Fatalf("Route(second) = %d, want 8", got)
	}
	if matchCalls != 2 {
		t.Fatalf("Match calls = %d, want 2", matchCalls)
	}
}

func TestBytecodeSplitRouterRouteCacheKeyIncludesNativeState(t *testing.T) {
	rule := sysnet.Rule{Type: "test", Rule: "native route"}
	var matchCalls int
	system := &sysnetdebug.System{
		RuleMatcher: func(sysnet.Rule, sockowner.FlowTuple) (bool, error) {
			matchCalls++
			return true, nil
		},
	}
	cfg, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System:        system,
		Rules:         []sysnet.Rule{rule},
		RuleCacheTTL:  -1,
		RouteCacheTTL: time.Minute,
		Route:         append(param16(OP_RULE, 0), OP_SLOT, 8),
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}

	pkt := ipv4TCPPacket([4]byte{10, 0, 0, 1}, [4]byte{192, 0, 2, 2}, 1, 2)
	if got := cfg.Route(pkt, 0, false); got != 0 {
		t.Fatalf("Route(non-native) = %d, want 0", got)
	}
	if got := cfg.Route(pkt, 0, true); got != 8 {
		t.Fatalf("Route(native first) = %d, want 8", got)
	}
	if got := cfg.Route(pkt, 0, true); got != 8 {
		t.Fatalf("Route(native second) = %d, want 8", got)
	}
	if matchCalls != 1 {
		t.Fatalf("Match calls = %d, want 1", matchCalls)
	}
}

func TestBytecodeSplitRouterRouteCacheKeyIncludesFlowEligibility(t *testing.T) {
	rule := sysnet.Rule{Type: "test", Rule: "well formed flow"}
	var matchCalls int
	system := &sysnetdebug.System{
		RuleMatcher: func(sysnet.Rule, sockowner.FlowTuple) (bool, error) {
			matchCalls++
			return true, nil
		},
	}
	cfg, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System:        system,
		Rules:         []sysnet.Rule{rule},
		RuleCacheTTL:  -1,
		RouteCacheTTL: time.Minute,
		Route:         append(param16(OP_RULE, 0), OP_SLOT, 8),
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}

	src := [4]byte{10, 0, 0, 1}
	dst := [4]byte{192, 0, 2, 2}
	valid := ipv4TCPPacket(src, dst, 1, 2)
	malformed := ipv4ShortTCPPacket(src, dst, 1, 2)
	if got := cfg.Route(valid, 0, true); got != 8 {
		t.Fatalf("Route(valid first) = %d, want 8", got)
	}
	if got := cfg.Route(malformed, 0, true); got != 0 {
		t.Fatalf("Route(malformed) = %d, want 0", got)
	}
	if got := cfg.Route(valid, 0, true); got != 8 {
		t.Fatalf("Route(valid second) = %d, want 8", got)
	}
	if matchCalls != 1 {
		t.Fatalf("Match calls = %d, want 1", matchCalls)
	}
}

func TestBytecodeSplitRouterRouteCacheKeyIncludesPortsPresentState(t *testing.T) {
	cfg, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System:        &sysnetdebug.System{},
		RouteCacheTTL: time.Minute,
		Route:         append(param16(OP_PORT, 0), OP_SLOT, 8),
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}

	src := [4]byte{10, 0, 0, 1}
	dst := [4]byte{192, 0, 2, 2}
	valid := ipv4TCPPacket(src, dst, 0, 0)
	noPorts := ipv4HeaderOnlyPacket(src, dst, 6)
	if got := cfg.Route(valid, 0, true); got != 8 {
		t.Fatalf("Route(valid first) = %d, want 8", got)
	}
	if got := cfg.Route(noPorts, 0, true); got != 0 {
		t.Fatalf("Route(no ports) = %d, want 0", got)
	}
	if got := cfg.Route(valid, 0, true); got != 8 {
		t.Fatalf("Route(valid second) = %d, want 8", got)
	}
}

func TestBytecodeSplitRouterRouteCacheKeyIncludesProtocol(t *testing.T) {
	cfg, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System:        &sysnetdebug.System{},
		RouteCacheTTL: time.Minute,
		Route:         append([]byte{OP_TCP}, OP_SLOT, 8),
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}

	src := [4]byte{10, 0, 0, 1}
	dst := [4]byte{192, 0, 2, 2}
	tcp := ipv4TCPPacket(src, dst, 1, 2)
	udp := ipv4UDPPacket(src, dst, 1, 2)
	if got := cfg.Route(tcp, 0, true); got != 8 {
		t.Fatalf("Route(tcp first) = %d, want 8", got)
	}
	if got := cfg.Route(udp, 0, true); got != 0 {
		t.Fatalf("Route(udp) = %d, want 0", got)
	}
	if got := cfg.Route(tcp, 0, true); got != 8 {
		t.Fatalf("Route(tcp second) = %d, want 8", got)
	}
}

func TestBytecodeSplitRouterSkipsMatcherForPacketsWithoutFlows(t *testing.T) {
	rule := sysnet.Rule{Type: "test", Rule: "flow only"}
	var matchCalls int
	system := &sysnetdebug.System{
		RuleMatcher: func(sysnet.Rule, sockowner.FlowTuple) (bool, error) {
			matchCalls++
			return true, nil
		},
	}
	cfg, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System:        system,
		Rules:         []sysnet.Rule{rule},
		RuleCacheTTL:  -1,
		RouteCacheTTL: -1,
		Route:         append(param16(OP_RULE, 0), OP_SLOT, 8),
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}

	src := [4]byte{10, 0, 0, 1}
	dst := [4]byte{192, 0, 2, 2}
	tests := []struct {
		name string
		pkt  []byte
	}{
		{name: "short IPv4", pkt: []byte{0x45}},
		{name: "TCP without ports", pkt: ipv4HeaderOnlyPacket(src, dst, 6)},
		{name: "UDP without ports", pkt: ipv4HeaderOnlyPacket(src, dst, 17)},
		{name: "ICMP", pkt: ipv4HeaderOnlyPacket(src, dst, 1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cfg.Route(tt.pkt, 0, true); got != 0 {
				t.Fatalf("Route() = %d, want 0", got)
			}
		})
	}
	if matchCalls != 0 {
		t.Fatalf("Match calls = %d, want 0", matchCalls)
	}
}

func TestBytecodeSplitRouterSkipsMatcherForNonNativePackets(t *testing.T) {
	rule := sysnet.Rule{Type: "test", Rule: "native only"}
	var matchCalls int
	system := &sysnetdebug.System{
		RuleMatcher: func(sysnet.Rule, sockowner.FlowTuple) (bool, error) {
			matchCalls++
			return true, nil
		},
	}
	cfg, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System: system,
		Rules:  []sysnet.Rule{rule},
		Route:  append(param16(OP_RULE, 0), OP_SLOT, 8),
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}

	if got := cfg.Route(
		ipv4TCPPacket([4]byte{10, 0, 0, 1}, [4]byte{192, 0, 2, 2}, 1, 2),
		0,
		false,
	); got != 0 {
		t.Fatalf("Route(non-native) = %d, want 0", got)
	}
	if matchCalls != 0 {
		t.Fatalf("Match calls = %d, want 0", matchCalls)
	}
}

func TestBytecodeSplitRouterReportsMentionedSlots(t *testing.T) {
	router, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System: &sysnetdebug.System{},
		Route: []byte{
			OP_TRUE, OP_SLOT, 4,
			OP_TRUE, OP_SLOT, 0,
			OP_TRUE, OP_DROP,
			OP_TRUE, OP_SLOT, 4,
			OP_TRUE, OP_SLOT, 16,
		},
	})
	if err != nil {
		t.Fatalf("NewBytecodeSplitRouter() error = %v", err)
	}

	got := router.MentionedSlots()
	want := []int{4, 16}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MentionedSlots() = %v, want %v", got, want)
	}

	got[0] = 99
	if got := router.MentionedSlots(); !reflect.DeepEqual(got, want) {
		t.Fatalf("MentionedSlots() after caller mutation = %v, want %v", got, want)
	}
}

func TestBytecodeSplitRouterValidation(t *testing.T) {
	_, err := NewBytecodeSplitRouter(SplitBytecodeRules{
		System: &sysnetdebug.System{},
		Route:  param16(OP_RULE, 0),
	})
	if err == nil ||
		!strings.Contains(err.Error(), "rule index 0 out of range 0") {
		t.Fatalf(
			"NewBytecodeSplitRouter() error = %v, want rule index error",
			err,
		)
	}
	_, err = NewBytecodeSplitRouter(SplitBytecodeRules{
		System: &sysnetdebug.System{},
		Route:  []byte{OP_DIAL, OP_SLOT, 1},
	})
	if err == nil ||
		!strings.Contains(err.Error(), "not valid for SplitRouter") {
		t.Fatalf(
			"NewBytecodeSplitRouter(method op) error = %v, want SplitRouter validation error",
			err,
		)
	}
	_, err = NewBytecodeSplitRouter(SplitBytecodeRules{})
	if err == nil || !strings.Contains(err.Error(), "system is nil") {
		t.Fatalf(
			"NewBytecodeSplitRouter(nil system) error = %v, want nil system error",
			err,
		)
	}
}

func param16(op byte, param uint16) []byte {
	out := []byte{op, 0, 0}
	binary.LittleEndian.PutUint16(out[1:], param)
	return out
}

func ip4(a, b, c, d byte) uint32 {
	return binary.BigEndian.Uint32([]byte{a, b, c, d})
}

func ipv4TCPPacket(src, dst [4]byte, srcPort, dstPort uint16) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	pkt[32] = 0x50
	return pkt
}

func ipv4UDPPacket(src, dst [4]byte, srcPort, dstPort uint16) []byte {
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint16(pkt[24:26], 8)
	return pkt
}

func ipv4HeaderOnlyPacket(src, dst [4]byte, proto uint8) []byte {
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = proto
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	return pkt
}

func ipv4ShortTCPPacket(src, dst [4]byte, srcPort, dstPort uint16) []byte {
	pkt := make([]byte, 24)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	return pkt
}
