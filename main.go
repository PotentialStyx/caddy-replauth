package mymodule

import (
	"crypto/ecdsa"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"
)

//go:embed auth.html
var AUTH_HTML []byte

func init() {
	caddy.RegisterModule(ReplAuth{})
}

type ReplAuth struct {
	IgnoreHost bool     `json:"ignoreHost,omitempty"`
	ForceAuth  bool     `json:"forceAuth,omitempty"`
	Hosts      []string `json:"hosts,omitempty"`
	pubKey     *ecdsa.PublicKey
	logger     *zap.Logger
}

func (authInstance *ReplAuth) Provision(ctx caddy.Context) error {
	authInstance.logger = ctx.Logger()

	if err := authInstance.reloadKey(); err != nil {
		return err
	}

	return nil
}

func (authInstance *ReplAuth) verifyToken(token string) (jwt.MapClaims, bool) {
	parsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return authInstance.pubKey, nil
	})
	if err != nil {
		authInstance.logger.Debug("Error verifying token", zap.Error(err))
	} else if claims, ok := parsed.Claims.(jwt.MapClaims); ok && parsed.Valid {
		if authInstance.IgnoreHost || slices.Contains(authInstance.Hosts, claims["host"].(string)) {
			return claims, true
		} else {
			authInstance.logger.Info("Host mismatch", zap.String("Host Given", claims["host"].(string)), zap.Strings("Hosts Allowed", authInstance.Hosts))
		}
	}
	return nil, false
}

func (authInstance *ReplAuth) ServeHTTP(writer http.ResponseWriter, request *http.Request, handler caddyhttp.Handler) error {
	if request.URL.Path == "/__replauth" {
		expiration := time.Now().Add(2 * 24 * time.Hour)
		token := request.URL.Query().Get("token")
		cookie := http.Cookie{Name: "REPL_AUTH", Value: token, Expires: expiration, HttpOnly: true, Secure: true}
		http.SetCookie(writer, &cookie)
		authInstance.logger.Debug("Auth request", zap.String("token", token))
		if request.URL.Query().Has("redirect") {
			http.Redirect(writer, request, request.URL.Query().Get("redirect"), http.StatusFound)
		}
		writer.WriteHeader(http.StatusOK)
		writer.Write([]byte{})
		return nil
	} else if request.URL.Path == "/__replauthuser" {
		REPL_AUTH := ""
		for _, cookie := range request.Cookies() {
			if cookie.Name == "REPL_AUTH" {
				REPL_AUTH = cookie.Value
				break
			}
		}

		if REPL_AUTH != "" {
			if claims, valid := authInstance.verifyToken(REPL_AUTH); valid {
				var response map[string]interface{} = map[string]interface{}{}

				id, err := strconv.Atoi(claims["sub"].(string))
				if err != nil {
					authInstance.logger.Warn("Error parsing id as int in __replauthuser", zap.String("Error", err.Error()))
					goto UNVERIFIED
				}

				response["id"] = id
				response["name"] = claims["name"].(string)
				response["roles"] = strings.Split(claims["roles"].(string), ",")
				response["teams"] = strings.Split(claims["teams"].(string), ",")
				response["bio"] = claims["bio"].(string)
				response["url"] = claims["url"].(string)
				response["profileImage"] = claims["profile_image"].(string)

				res, err := json.Marshal(response)
				if err != nil {
					return err
				}

				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(http.StatusOK)
				writer.Write(res)
				return nil
			}
		}

	UNVERIFIED:
		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write([]byte("User is not logged in"))
		return nil
	}

	REPL_AUTH := ""
	for _, cookie := range request.Cookies() {
		if cookie.Name == "REPL_AUTH" {
			REPL_AUTH = cookie.Value
			break
		}
	}

	for name := range request.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-replit-user-") {
			request.Header.Del(name)
		}
	}

	didSet := false
	if REPL_AUTH != "" {
		if claims, valid := authInstance.verifyToken(REPL_AUTH); valid {
			didSet = true
			request.Header.Set("X-Replit-User-Name", claims["name"].(string))
			request.Header.Set("X-Replit-User-Id", claims["sub"].(string))
			request.Header.Set("X-Replit-User-Bio", claims["bio"].(string))
			request.Header.Set("X-Replit-User-Profile-Image", claims["profile_image"].(string))
			request.Header.Add("X-Replit-User-Roles", claims["roles"].(string))
			request.Header.Add("X-Replit-User-Teams", claims["teams"].(string))
			request.Header.Add("X-Replit-User-Url", claims["url"].(string))
		}
	}

	if !didSet {
		if authInstance.ForceAuth {
			writer.Header().Set("Content-Type", "text/html; charset=utf-8")
			writer.WriteHeader(http.StatusUnauthorized)
			writer.Write(AUTH_HTML)
			return nil
		}

		request.Header.Add("X-Replit-User-Bio", "")
		request.Header.Add("X-Replit-User-Id", "")
		request.Header.Add("X-Replit-User-Name", "")
		request.Header.Add("X-Replit-User-Profile-Image", "")
		request.Header.Add("X-Replit-User-Roles", "")
		request.Header.Add("X-Replit-User-Teams", "")
		request.Header.Add("X-Replit-User-Url", "")
	}

	return handler.ServeHTTP(writer, request)
}

func (authInstance *ReplAuth) reloadKey() error {
	res, err := http.Get("https://replit.com/pubkeys/v1/repl-auth-public-key")
	if err != nil {
		return err
	}

	_data, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	realdata := map[string]string{}
	err = json.Unmarshal(_data, &realdata)
	if err != nil {
		return caddyhttp.ErrNotImplemented
	}

	block, _ := pem.Decode([]byte(realdata["prod:1"]))
	if block == nil {
		return errors.New("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	authInstance.pubKey = pub.(*ecdsa.PublicKey)
	return nil
}

func (authInstance ReplAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.handlers.replauth",
		New: func() caddy.Module {
			authInstance := new(ReplAuth)

			return authInstance
		},
	}
}

var (
	_ caddyhttp.MiddlewareHandler = (*ReplAuth)(nil)
)
