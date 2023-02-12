package services

import (
	"crypto/sha1"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

type StandardClaims struct {
	Rate        string `json:"rate"`
	Connections int    `json:"connections"`
	Role        string `json:"role"`
	SessionID   string `json:"sessionID"`
	Domain      string `json:"domain"`
	jwt.StandardClaims
}

const (
	webHostFlag             = "host"
	webPortFlag             = "port"
	restAPIHostFlag         = "rest-api-host"
	restAPIPortFlag         = "rest-api-port"
	basicRateFlag           = "basic-rate"
	proRateFlag             = "pro-rate"
	ultraRateFlag           = "ultra-rate"
	megaRateFlag            = "mega-rate"
	basicConFlag            = "basic-connections"
	proConFlag              = "pro-connections"
	ultraConFlag            = "ultra-connections"
	megaConFlag             = "mega-connections"
	rapidAPIProxySecretFlag = "rapid-api-proxy-secret"
	webtorAPIKeyFlag        = "webtor-api-key"
	webtorAPISecretFlag     = "webtor-api-secret"
)

type SubscriptionType string

const (
	SubscriptionTypeBasic SubscriptionType = "basic"
	SubscriptionTypePro   SubscriptionType = "pro"
	SubscriptionTypeUltra SubscriptionType = "ultra"
	SubscriptionTypeMega  SubscriptionType = "mega"
)

type Features struct {
	Rate        string
	Connections int
}

type Web struct {
	host        string
	port        int
	raHost      string
	raPort      int
	rates       map[SubscriptionType]Features
	rapidSecret string
	wKey        string
	wSecret     string
	ln          net.Listener
}

func NewWeb(c *cli.Context) *Web {
	return &Web{
		host:        c.String(webHostFlag),
		port:        c.Int(webPortFlag),
		raHost:      c.String(restAPIHostFlag),
		raPort:      c.Int(restAPIPortFlag),
		rapidSecret: c.String(rapidAPIProxySecretFlag),
		rates: map[SubscriptionType]Features{
			SubscriptionTypeBasic: Features{
				Rate:        c.String(basicRateFlag),
				Connections: c.Int(basicConFlag),
			},
			SubscriptionTypePro: Features{
				Rate:        c.String(proRateFlag),
				Connections: c.Int(proConFlag),
			},
			SubscriptionTypeUltra: Features{
				Rate:        c.String(ultraRateFlag),
				Connections: c.Int(ultraConFlag),
			},
			SubscriptionTypeMega: Features{
				Rate:        c.String(megaRateFlag),
				Connections: c.Int(megaConFlag),
			},
		},
		wKey:    c.String(webtorAPIKeyFlag),
		wSecret: c.String(webtorAPISecretFlag),
	}
}

func RegisterWebFlags(f []cli.Flag) []cli.Flag {
	return append(f,
		cli.StringFlag{
			Name:   webHostFlag,
			Usage:  "listening host",
			Value:  "",
			EnvVar: "WEB_HOST",
		},
		cli.IntFlag{
			Name:   webPortFlag,
			Usage:  "http listening port",
			Value:  8080,
			EnvVar: "WEB_PORT",
		},
		cli.StringFlag{
			Name:   restAPIHostFlag,
			Usage:  "rest-api host",
			EnvVar: "REST_API_SERVICE_HOST",
		},
		cli.IntFlag{
			Name:   restAPIPortFlag,
			Usage:  "rest-api port",
			EnvVar: "REST_API_SERVICE_PORT",
			Value:  80,
		},
		cli.StringFlag{
			Name:   basicRateFlag,
			Usage:  "basic rate",
			EnvVar: "BASIC_RATE",
			Value:  "20M",
		},
		cli.StringFlag{
			Name:   proRateFlag,
			Usage:  "pro rate",
			EnvVar: "PRO_RATE",
			Value:  "100M",
		},
		cli.StringFlag{
			Name:   ultraRateFlag,
			Usage:  "ultra rate",
			EnvVar: "ULTRA_RATE",
			Value:  "250M",
		},
		cli.StringFlag{
			Name:   megaRateFlag,
			Usage:  "mega rate",
			EnvVar: "MEGA_RATE",
			Value:  "1000M",
		},
		cli.IntFlag{
			Name:   basicConFlag,
			Usage:  "basic connections",
			EnvVar: "BASIC_CONNECTIONS",
			Value:  2,
		},
		cli.IntFlag{
			Name:   proConFlag,
			Usage:  "pro connections",
			EnvVar: "PRO_CONNECTIONS",
			Value:  10,
		},
		cli.IntFlag{
			Name:   ultraConFlag,
			Usage:  "ultra connections",
			EnvVar: "ULTRA_CONNECTIONS",
			Value:  25,
		},
		cli.IntFlag{
			Name:   megaConFlag,
			Usage:  "mega connections",
			EnvVar: "MEGA_CONNECTIONS",
			Value:  100,
		},
		cli.StringFlag{
			Name:   rapidAPIProxySecretFlag,
			Usage:  "rapid api proxy secret",
			EnvVar: "RAPID_API_PROXY_SECRET",
		},
		cli.StringFlag{
			Name:   webtorAPIKeyFlag,
			Usage:  "webtor api key",
			EnvVar: "WEBTOR_API_KEY",
		},
		cli.StringFlag{
			Name:   webtorAPISecretFlag,
			Usage:  "webtor api secret",
			EnvVar: "WEBTOR_API_SECRET",
		},
	)
}
func (s *Web) newProxy(addr string) (*httputil.ReverseProxy, error) {
	url, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}

	return httputil.NewSingleHostReverseProxy(url), nil
}

func (s *Web) proxyRequestHandler(proxy *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-RapidAPI-Proxy-Secret") != s.rapidSecret {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		subType := SubscriptionTypeBasic
		rapSub := strings.ToLower(r.Header.Get("X-RapidAPI-Subscription"))
		for k := range s.rates {
			if strings.HasPrefix(rapSub, string(k)) {
				subType = k
				break
			}
		}
		features := s.rates[subType]
		claims := &StandardClaims{
			SessionID:   fmt.Sprintf("%x", sha1.Sum([]byte(r.Header.Get("X-RapidAPI-User")+features.Rate+strconv.Itoa(features.Connections)))),
			Role:        string(subType),
			Rate:        features.Rate,
			Connections: features.Connections,
			Domain:      "rapidapi.com",
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(24 * 7 * time.Hour).Unix(),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(s.wSecret))
		if err != nil {
			log.WithError(err).Error("failed to generate token")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		r.Header.Set("X-Token", tokenString)
		r.Header.Set("X-Api-Key", s.wKey)
		proxy.ServeHTTP(w, r)
	}
}

func (s *Web) Serve() error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	ln, err := net.Listen("tcp", addr)
	s.ln = ln
	if err != nil {
		return errors.Wrap(err, "failed to listen to tcp connection")
	}
	mux := http.NewServeMux()
	raAddr := fmt.Sprintf("http://%s:%d", s.raHost, s.raPort)
	pr, err := s.newProxy(raAddr)
	if err != nil {
		return err
	}
	mux.HandleFunc("/", s.proxyRequestHandler(pr))
	log.Infof("serving Web at %v", addr)
	return http.Serve(s.ln, mux)
}

func (s *Web) Close() {
	log.Info("closing Web")
	defer func() {
		log.Info("Web closed")
	}()
	if s.ln != nil {
		s.ln.Close()
	}
}
