package store

import "testing"

func TestMatcherForms(t *testing.T) {
	m := NewMatcher()
	m.Add("example.com", "self")
	m.Add("*.wild.com", "wild")
	m.Add("=exact.com", "exact")
	m.Add("keyword:telegram", "kw")

	cases := []struct {
		name string
		want string // "" = no match
	}{
		{"example.com", "self"},
		{"a.b.example.com", "self"},
		{"notexample.com", ""},
		{"example.com.evil.net", ""},
		{"wild.com", ""},
		{"sub.wild.com", "wild"},
		{"deep.sub.wild.com", "wild"},
		{"exact.com", "exact"},
		{"sub.exact.com", ""},
		{"cdn-telegram.org", "kw"},
		{"EXAMPLE.COM", "self"},
		{"", ""},
	}
	for _, c := range cases {
		got := m.Match(c.name)
		if c.want == "" {
			if len(got) != 0 {
				t.Errorf("Match(%q) = %v, want no match", c.name, got)
			}
			continue
		}
		if len(got) != 1 || got[0] != c.want {
			t.Errorf("Match(%q) = %v, want [%s]", c.name, got, c.want)
		}
	}
}

func TestNormalizeDomains(t *testing.T) {
	got := NormalizeDomains([]string{
		"HTTPS://Example.com/path?q=1",
		"  *.Sub.Example.com  ",
		"=exact.example.com",
		"example.com",
		"example.com",
		"# comment",
		"not a domain!",
		"user@mail.example.org",
		"1.2.3.4",
	})
	want := []string{"*.sub.example.com", "=exact.example.com", "example.com", "mail.example.org"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestClientActive(t *testing.T) {
	c := Client{Enabled: true}
	if !c.Active(nowForTest()) {
		t.Fatal("fresh client should be active")
	}
	c.Enabled = false
	if c.Active(nowForTest()) {
		t.Fatal("disabled client must not be active")
	}
	c.Enabled = true
	c.QuotaBytes = 100
	c.UsedBytes = 100
	if c.Active(nowForTest()) {
		t.Fatal("client over quota must not be active")
	}
}

func TestRouteDeleteDetachesClients(t *testing.T) {
	dir := t.TempDir() + "/state.json"
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.CreateRoute(Route{Name: "r", Domains: []string{"a.com"}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.CreateClient(Client{Name: "c", Enabled: true, RouteIDs: []string{r.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRoute(r.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.Client(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.RouteIDs) != 0 {
		t.Fatalf("route id still attached: %v", got.RouteIDs)
	}
}

func TestPasswordRoundTrip(t *testing.T) {
	s, err := Open(t.TempDir() + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetPassword("s3cret-pass", true); err != nil {
		t.Fatal(err)
	}
	if !s.VerifyPassword("s3cret-pass") {
		t.Fatal("password should verify")
	}
	if s.VerifyPassword("wrong") {
		t.Fatal("wrong password must not verify")
	}
	if !s.TemporaryPassword() {
		t.Fatal("temporary flag lost")
	}
}
