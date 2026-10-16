package ports

import (
	"maps"
	"net/netip"
	"os"
	"slices"
	"testing"

	"github.com/guillaume86/autofwd/internal/procnet"
)

func TestParseSet(t *testing.T) {
	tests := []struct {
		in      string
		want    Set
		wantErr bool
	}{
		{in: "", want: nil},
		{in: " , ,", want: nil},
		{in: "5432", want: Set{{5432, 5432}}},
		{in: "5432,6379,40000-50000", want: Set{{5432, 5432}, {6379, 6379}, {40000, 50000}}},
		{in: " 22 , 8000 - 8100 ", want: Set{{22, 22}, {8000, 8100}}},
		{in: "1-65535", want: Set{{1, 65535}}},
		{in: "0", wantErr: true},
		{in: "65536", wantErr: true},
		{in: "abc", wantErr: true},
		{in: "100-50", wantErr: true},
		{in: "100-", wantErr: true},
		{in: "-100", wantErr: true},
		{in: "1-2-3", wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParseSet(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseSet(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("ParseSet(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestSetStringRoundTrip(t *testing.T) {
	s, err := ParseSet("5432, 6379,40000-50000")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.String(); got != "5432,6379,40000-50000" {
		t.Errorf("String() = %q", got)
	}
}

func TestFilter(t *testing.T) {
	ignore, _ := ParseSet("5432,6379,40000-50000")
	only, _ := ParseSet("80,3000-3001")
	tests := []struct {
		name string
		f    Filter
		port uint16
		want bool
	}{
		{"below min", Filter{MinPort: 1024}, 1023, false},
		{"at min", Filter{MinPort: 1024}, 1024, true},
		{"no min", Filter{}, 22, true},
		{"ignored single", Filter{MinPort: 1024, Ignore: ignore}, 5432, false},
		{"ignored range low edge", Filter{MinPort: 1024, Ignore: ignore}, 40000, false},
		{"ignored range high edge", Filter{MinPort: 1024, Ignore: ignore}, 50000, false},
		{"just past range", Filter{MinPort: 1024, Ignore: ignore}, 50001, true},
		{"only allows listed", Filter{MinPort: 1024, Ignore: ignore, Only: only}, 3001, true},
		{"only rejects unlisted", Filter{MinPort: 1024, Only: only}, 3002, false},
		{"only overrides min-port", Filter{MinPort: 1024, Only: only}, 80, true},
		{"only overrides ignore", Filter{Ignore: Set{{3000, 3000}}, Only: only}, 3000, true},
	}
	for _, tt := range tests {
		if got := tt.f.Allow(tt.port); got != tt.want {
			t.Errorf("%s: Allow(%d) = %v, want %v", tt.name, tt.port, got, tt.want)
		}
	}
}

func l(s string) procnet.Listener {
	ap := netip.MustParseAddrPort(s)
	return procnet.Listener{Addr: ap.Addr(), Port: ap.Port()}
}

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func TestSelectTargets(t *testing.T) {
	tests := []struct {
		name string
		in   []procnet.Listener
		want map[uint16]netip.AddrPort
	}{
		{"v4 wildcard", []procnet.Listener{l("0.0.0.0:3000")}, map[uint16]netip.AddrPort{3000: ap("127.0.0.1:3000")}},
		{"v6 wildcard", []procnet.Listener{l("[::]:3000")}, map[uint16]netip.AddrPort{3000: ap("127.0.0.1:3000")}},
		{"127.0.0.1", []procnet.Listener{l("127.0.0.1:3000")}, map[uint16]netip.AddrPort{3000: ap("127.0.0.1:3000")}},
		{"127.0.1.1 normalised", []procnet.Listener{l("127.0.1.1:3000")}, map[uint16]netip.AddrPort{3000: ap("127.0.0.1:3000")}},
		{"127.255.255.254 normalised", []procnet.Listener{l("127.255.255.254:3000")}, map[uint16]netip.AddrPort{3000: ap("127.0.0.1:3000")}},
		{"mapped wildcard", []procnet.Listener{{Addr: netip.MustParseAddr("::ffff:0.0.0.0"), Port: 3000}}, map[uint16]netip.AddrPort{3000: ap("127.0.0.1:3000")}},
		{"mapped loopback", []procnet.Listener{{Addr: netip.MustParseAddr("::ffff:127.0.0.1"), Port: 3000}}, map[uint16]netip.AddrPort{3000: ap("127.0.0.1:3000")}},
		{"::1 alone", []procnet.Listener{l("[::1]:3000")}, map[uint16]netip.AddrPort{3000: ap("[::1]:3000")}},
		{"::1 loses to 127.0.0.1", []procnet.Listener{l("[::1]:3000"), l("127.0.0.1:3000")}, map[uint16]netip.AddrPort{3000: ap("127.0.0.1:3000")}},
		{"::1 loses to wildcard", []procnet.Listener{l("[::1]:3000"), l("0.0.0.0:3000")}, map[uint16]netip.AddrPort{3000: ap("127.0.0.1:3000")}},
		{"::1 loses to specific v4", []procnet.Listener{l("[::1]:3000"), l("10.0.0.5:3000")}, map[uint16]netip.AddrPort{3000: ap("10.0.0.5:3000")}},
		{"specific v4", []procnet.Listener{l("10.0.0.5:5432")}, map[uint16]netip.AddrPort{5432: ap("10.0.0.5:5432")}},
		{"loopback beats specific v4", []procnet.Listener{l("10.0.0.5:3000"), l("127.0.0.1:3000")}, map[uint16]netip.AddrPort{3000: ap("127.0.0.1:3000")}},
		{"specific v4 tie is deterministic", []procnet.Listener{l("10.0.0.9:3000"), l("10.0.0.5:3000")}, map[uint16]netip.AddrPort{3000: ap("10.0.0.5:3000")}},
		{"specific v6", []procnet.Listener{l("[2001:db8::10]:9443")}, map[uint16]netip.AddrPort{9443: ap("[2001:db8::10]:9443")}},
		{"::1 beats specific v6", []procnet.Listener{l("[2001:db8::10]:9443"), l("[::1]:9443")}, map[uint16]netip.AddrPort{9443: ap("[::1]:9443")}},
		{"link-local with zone", []procnet.Listener{l("[fe80::1%eth0]:8000")}, map[uint16]netip.AddrPort{8000: ap("[fe80::1%eth0]:8000")}},
		{"link-local without zone dropped", []procnet.Listener{l("[fe80::1]:8000")}, map[uint16]netip.AddrPort{}},
	}
	for _, tt := range tests {
		got, _ := Select(tt.in, Filter{})
		if !maps.Equal(got, tt.want) {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestSelectUnusable(t *testing.T) {
	_, unusable := Select([]procnet.Listener{l("[fe80::1]:8000"), l("[fe80::2]:9000"), l("0.0.0.0:9000")}, Filter{})
	if want := []procnet.Listener{l("[fe80::1]:8000")}; !slices.Equal(unusable, want) {
		t.Errorf("unusable = %v, want %v (9000 has a usable listener)", unusable, want)
	}
}

func TestSelectAppliesFilter(t *testing.T) {
	ignore, _ := ParseSet("8080")
	got, _ := Select([]procnet.Listener{l("0.0.0.0:22"), l("0.0.0.0:8080"), l("127.0.0.1:3000")}, Filter{MinPort: 1024, Ignore: ignore})
	if want := map[uint16]netip.AddrPort{3000: ap("127.0.0.1:3000")}; !maps.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestSelectFixtures runs the full pipeline over the parser fixtures.
func TestSelectFixtures(t *testing.T) {
	var data []byte
	for _, name := range []string{"tcp", "tcp6"} {
		b, err := os.ReadFile("../procnet/testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, b...)
	}
	ls, err := procnet.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	got, unusable := Select(ls, Filter{MinPort: 1024})
	want := map[uint16]netip.AddrPort{
		3000:  ap("127.0.0.1:3000"), // 127.0.0.1 and ::1 both listen: IPv4 wins
		4000:  ap("127.0.0.1:4000"), // ::
		5001:  ap("[::1]:5001"),
		5432:  ap("10.0.0.5:5432"),
		6001:  ap("127.0.0.1:6001"), // ::ffff:127.0.0.1
		7000:  ap("127.0.0.1:7000"), // ::ffff:0.0.0.0
		8080:  ap("127.0.0.1:8080"),
		9090:  ap("127.0.0.1:9090"), // 127.0.1.1
		9443:  ap("[2001:db8::10]:9443"),
		41641: ap("[fd7a:115c:a1e0:ab12:4843:cd96:6263:a]:41641"),
	}
	if !maps.Equal(got, want) {
		t.Errorf("got  %v\nwant %v", got, want)
	}
	if len(unusable) != 1 || unusable[0].Port != 8000 {
		t.Errorf("unusable = %v, want the fe80:: listener on 8000", unusable)
	}
}
