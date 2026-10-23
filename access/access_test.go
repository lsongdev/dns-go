package access

import (
	"net/netip"
	"sync"
	"testing"
)

func mustNetworks(t *testing.T, entries ...string) []netip.Prefix {
	t.Helper()
	p, err := ParseNetworks(entries)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func check(c *Controller, addr, id string) Decision {
	return c.Check(Request{Addr: netip.MustParseAddr(addr), ClientID: id})
}

func TestCheckOrder(t *testing.T) {
	c, err := New(Rules{
		Allow: mustNetworks(t, "private"),
		Deny:  mustNetworks(t, "10.9.0.0/16"),
		Clients: []Client{
			{Name: "phone", IDs: []string{"Ph0ne-1"}},
			{Name: "nas", Networks: mustNetworks(t, "192.168.1.0/24")},
			{Name: "nas-admin", Networks: mustNetworks(t, "192.168.1.2")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		addr, id string
		allowed  bool
		client   string
	}{
		{"127.0.0.1", "", true, ""},
		{"::ffff:10.0.0.1", "", true, ""}, // IPv4-mapped is unmapped
		{"fd00::1", "", true, ""},
		{"8.8.8.8", "", false, ""},
		{"8.8.8.8", "ph0ne-1", true, "phone"}, // IDs are case-insensitive
		{"8.8.8.8", "other", false, ""},
		{"10.9.1.1", "ph0ne-1", false, ""}, // deny beats ID
		{"192.168.1.7", "", true, "nas"},
		{"192.168.1.2", "", true, "nas-admin"}, // most specific network wins
	}
	for _, tc := range cases {
		d := check(c, tc.addr, tc.id)
		if d.Allowed != tc.allowed || d.Client != tc.client {
			t.Errorf("%s id=%q: got %+v", tc.addr, tc.id, d)
		}
		if !d.Allowed && (d.Action != Refuse || d.Reason == "") {
			t.Errorf("%s: refusal needs action and reason: %+v", tc.addr, d)
		}
	}
}

func TestNilAllowMeansEveryoneEmptyMeansNoOne(t *testing.T) {
	open, _ := New(Rules{})
	if !check(open, "8.8.8.8", "").Allowed || !open.AllowsEveryone() {
		t.Fatal("nil Allow should admit everyone")
	}
	closed, _ := New(Rules{Allow: []netip.Prefix{}, Clients: []Client{{Name: "a", IDs: []string{"x1"}}}})
	if check(closed, "127.0.0.1", "").Allowed || closed.AllowsEveryone() {
		t.Fatal("empty Allow should admit no one without an ID")
	}
	if !check(closed, "127.0.0.1", "x1").Allowed {
		t.Fatal("client IDs still work with an empty Allow")
	}
	any, _ := New(Rules{Allow: mustNetworks(t, "0.0.0.0/0")})
	if !any.AllowsEveryone() {
		t.Fatal("0.0.0.0/0 admits everyone")
	}
}

func TestSetValidation(t *testing.T) {
	c, _ := New(Rules{Clients: []Client{{Name: "ok", IDs: []string{"good"}}}})
	bad := []Rules{
		{DenyAction: "ignore"},
		{Clients: []Client{{Name: ""}}},
		{Clients: []Client{{Name: "a"}, {Name: "a"}}},
		{Clients: []Client{{Name: "a", IDs: []string{"has.dot"}}}},
		{Clients: []Client{{Name: "a", IDs: []string{"-lead"}}}},
		{Clients: []Client{{Name: "a", IDs: []string{"same"}}, {Name: "b", IDs: []string{"SAME"}}}},
	}
	for _, r := range bad {
		if err := c.Set(r); err == nil {
			t.Errorf("Set(%+v) should fail", r)
		}
	}
	if d := check(c, "8.8.8.8", "good"); !d.Allowed || d.Client != "ok" {
		t.Fatal("failed Set must keep the previous rules")
	}
}

func TestRulesAreCopied(t *testing.T) {
	r := Rules{Allow: mustNetworks(t, "10.0.0.0/8"), Clients: []Client{{Name: "a", IDs: []string{"x"}}}}
	c, _ := New(r)
	r.Clients[0].IDs[0] = "changed"
	got := c.Rules()
	got.Allow[0] = netip.MustParsePrefix("0.0.0.0/0")
	if c.Rules().Clients[0].IDs[0] != "x" || check(c, "8.8.8.8", "").Allowed {
		t.Fatal("controller aliases caller data")
	}
}

func TestParseNetworks(t *testing.T) {
	got := mustNetworks(t, "192.168.1.5", "10.1.2.3/8", "::ffff:1.2.3.4", "2001:db8::1")
	want := []string{"192.168.1.5/32", "10.0.0.0/8", "1.2.3.4/32", "2001:db8::1/128"}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("%d: %s, want %s", i, got[i], want[i])
		}
	}
	if _, err := ParseNetworks([]string{"10.0.0.0/33"}); err == nil {
		t.Fatal("bad prefix accepted")
	}
}

func TestConcurrentCheckAndSet(t *testing.T) {
	c, _ := New(Rules{Allow: Private})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				check(c, "192.168.1.1", "")
			}
		}()
	}
	for i := 0; i < 100; i++ {
		c.Set(Rules{Allow: Private, Clients: []Client{{Name: "a", IDs: []string{"x"}}}})
	}
	wg.Wait()
}
