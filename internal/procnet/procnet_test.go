package procnet

import (
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
)

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func listeners(t *testing.T, pairs ...string) []Listener {
	t.Helper()
	var out []Listener
	for _, p := range pairs {
		ap := netip.MustParseAddrPort(p)
		out = append(out, Listener{Addr: ap.Addr(), Port: ap.Port()})
	}
	return out
}

func TestParseTCP4(t *testing.T) {
	got, err := Parse(mustRead(t, "tcp"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := listeners(t,
		"127.0.0.1:3000",
		"0.0.0.0:8080",
		"127.0.0.53:53",
		"0.0.0.0:22",
		"10.0.0.5:5432",
		"127.0.1.1:9090",
	)
	if !slices.Equal(got, want) {
		t.Errorf("got  %v\nwant %v", got, want)
	}
}

func TestParseTCP6(t *testing.T) {
	got, err := Parse(mustRead(t, "tcp6"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := listeners(t,
		"[::]:4000",
		"[::1]:5001",
		"[::1]:3000",
		"127.0.0.1:6001", // ::ffff:127.0.0.1, unmapped
		"0.0.0.0:7000",   // ::ffff:0.0.0.0, unmapped
		"[fe80::20f:1eff:feb8:a595]:8000",
		"[fd7a:115c:a1e0:ab12:4843:cd96:6263:a]:41641",
		"[2001:db8::10]:9443",
	)
	if !slices.Equal(got, want) {
		t.Errorf("got  %v\nwant %v", got, want)
	}
	for _, l := range got {
		if l.Addr.Is4In6() {
			t.Errorf("%v: mapped address was not unmapped", l)
		}
	}
}

func TestParseConcatenated(t *testing.T) {
	// The discovery loop runs `cat /proc/net/tcp /proc/net/tcp6`, so the
	// second header sits in the middle of the input.
	data := append(mustRead(t, "tcp"), mustRead(t, "tcp6")...)
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 6+8 {
		t.Errorf("got %d listeners, want 14: %v", len(got), got)
	}
}

func TestParseZone(t *testing.T) {
	const in = "   0: 000080FE00000000FF1E0F0295A5B8FE%eth0:1F40 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000 0 1 1 0 100 0 0 10 0\n" +
		"   1: 0000000000000000FFFF00000100007F%lo:1771 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000 0 1 1 0 100 0 0 10 0\n"
	got, err := Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []Listener{
		{Addr: netip.MustParseAddr("fe80::20f:1eff:feb8:a595%eth0"), Port: 8000},
		{Addr: netip.MustParseAddr("127.0.0.1"), Port: 6001},
	}
	if !slices.Equal(got, want) {
		t.Errorf("got  %v\nwant %v", got, want)
	}
}

func TestParseCRLFAndLowercase(t *testing.T) {
	in := "  sl  local_address rem_address   st\r\n   0: 0100007f:0bb8 00000000:0000 0a 00000000:00000000\r\n"
	got, err := Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if want := listeners(t, "127.0.0.1:3000"); !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseMalformedRowsAreSkipped(t *testing.T) {
	in := strings.Join([]string{
		"  sl  local_address rem_address   st",
		"   0: 0100007F:0BB8 00000000:0000 0A 00000000:00000000",
		"   1: garbage",
		"   2: 0100007F 00000000:0000 0A",
		"   3: 0100ZZ7F:0BB8 00000000:0000 0A",
		"   4: 0100007F:FFFFF 00000000:0000 0A",
		"   5: 01007F:0BB8 00000000:0000 0A",
		"   6: 00000000:1F90 00000000:0000 0A 00000000:00000000",
		"",
	}, "\n")
	got, err := Parse([]byte(in))
	if want := listeners(t, "127.0.0.1:3000", "0.0.0.0:8080"); !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if err == nil {
		t.Fatal("expected an error describing the malformed rows")
	}
	for _, line := range []string{"line 3", "line 4", "line 5", "line 6", "line 7"} {
		if !strings.Contains(err.Error(), line) {
			t.Errorf("error %q does not mention %s", err, line)
		}
	}
}

func TestParseEmpty(t *testing.T) {
	got, err := Parse(nil)
	if err != nil || len(got) != 0 {
		t.Errorf("Parse(nil) = %v, %v", got, err)
	}
}
