package apxchallenge

import "github.com/caddyserver/caddy/v2"

func init() {
	caddy.RegisterModule(&ChallengeHandler{})
	caddy.RegisterModule(&VerifyEndpointHandler{})
	caddy.RegisterModule(&VerifyHandler{})
}
