package services

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Token bytes must not change across JWT library swaps: torrent-http-proxy
// and rest-api validate what the gateway signs.
func TestTokenEncodingIsStable(t *testing.T) {
	claims := &StandardClaims{
		SessionID:      "abc",
		Role:           "pro",
		Rate:           "100M",
		Connections:    10,
		Domain:         "rapidapi.com",
		StandardClaims: jwt.StandardClaims{ExpiresAt: 1700000000},
	}
	got, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	const want = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyYXRlIjoiMTAwTSIsImNvbm5lY3Rpb25zIjoxMCwicm9sZSI6InBybyIsInNlc3Npb25JRCI6ImFiYyIsImRvbWFpbiI6InJhcGlkYXBpLmNvbSIsImV4cCI6MTcwMDAwMDAwMH0.cdVu6_a_p1Fx3P3wu4GF0aBRMrATg3rrear78NbVPC0"
	if got != want {
		t.Fatalf("token changed:\n got %s\nwant %s", got, want)
	}
}

func TestProxyHandler(t *testing.T) {
	var gotToken, gotKey string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken, gotKey = r.Header.Get("X-Token"), r.Header.Get("X-Api-Key")
	}))
	defer upstream.Close()
	s := &Web{
		rapidSecret: "proxy-secret",
		wKey:        "key",
		wSecret:     "secret",
		rates: map[SubscriptionType]Features{
			SubscriptionTypeBasic: {Rate: "20M", Connections: 2},
			SubscriptionTypePro:   {Rate: "100M", Connections: 10},
		},
	}
	pr, err := s.newProxy(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	h := s.proxyRequestHandler(pr)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-RapidAPI-Proxy-Secret", "wrong")
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusForbidden || gotToken != "" {
		t.Fatalf("wrong proxy secret: code %d, upstream token %q", rec.Code, gotToken)
	}

	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-RapidAPI-Proxy-Secret", "proxy-secret")
	req.Header.Set("X-RapidAPI-Subscription", "PRO")
	req.Header.Set("X-RapidAPI-User", "u1")
	h(httptest.NewRecorder(), req)
	if gotKey != "key" {
		t.Fatalf("X-Api-Key %q", gotKey)
	}
	c := &StandardClaims{}
	tok, err := jwt.ParseWithClaims(gotToken, c, func(*jwt.Token) (interface{}, error) { return []byte("secret"), nil })
	if err != nil || !tok.Valid || tok.Method != jwt.SigningMethodHS256 {
		t.Fatalf("token %q: valid=%v err=%v", gotToken, tok != nil && tok.Valid, err)
	}
	exp := time.Now().Add(7 * 24 * time.Hour).Unix()
	if c.Role != "pro" || c.Rate != "100M" || c.Connections != 10 || c.Domain != "rapidapi.com" ||
		len(c.SessionID) != 40 || c.ExpiresAt < exp-60 || c.ExpiresAt > exp {
		t.Fatalf("claims %+v", c)
	}
}

func TestRapidAPIUid(t *testing.T) {
	if got := rapidAPIUid("u1"); got != "124795966a51f08416371e3cfc7ac802eb3d5f05" {
		t.Fatalf("rapidAPIUid(u1) = %s, want sha1(\"rapidapi:u1\")", got)
	}
	if rapidAPIUid("u1") == "c5ea71554c774daf7fab320fc3476afc0617eb00" {
		t.Fatal("uid without the rapidapi: prefix can collide with a site uid")
	}
	if got := rapidAPIUid(""); got != "" {
		t.Fatalf("empty user: uid %q, want none", got)
	}
}

func TestProxyHandlerUid(t *testing.T) {
	var gotToken string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { gotToken = r.Header.Get("X-Token") }))
	defer upstream.Close()
	s := &Web{rapidSecret: "proxy-secret", wKey: "key", wSecret: "secret",
		rates: map[SubscriptionType]Features{SubscriptionTypeBasic: {Rate: "20M", Connections: 2}}}
	pr, _ := s.newProxy(upstream.URL)
	h := s.proxyRequestHandler(pr)
	claimsOf := func(user, clientToken string) jwt.MapClaims {
		req := httptest.NewRequest("GET", "/resource/x", nil)
		req.Header.Set("X-RapidAPI-Proxy-Secret", "proxy-secret")
		if user != "" {
			req.Header.Set("X-RapidAPI-User", user)
		}
		if clientToken != "" {
			req.Header.Set("X-Token", clientToken)
		}
		h(httptest.NewRecorder(), req)
		m := jwt.MapClaims{}
		if _, err := jwt.ParseWithClaims(gotToken, m, func(*jwt.Token) (interface{}, error) { return []byte("secret"), nil }); err != nil {
			t.Fatal(err)
		}
		return m
	}
	if m := claimsOf("u1", ""); m["uid"] != "124795966a51f08416371e3cfc7ac802eb3d5f05" {
		t.Fatalf("uid claim %v", m["uid"])
	}
	if m := claimsOf("", ""); m["uid"] != nil {
		t.Fatalf("empty user must carry no uid claim, got %v", m["uid"])
	}
	forged, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"uid": strings.Repeat("0", 40)}).SignedString([]byte("secret"))
	if m := claimsOf("u1", forged); m["uid"] != "124795966a51f08416371e3cfc7ac802eb3d5f05" {
		t.Fatalf("client X-Token reached upstream: uid %v", m["uid"])
	}
}
