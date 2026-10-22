package services

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
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
