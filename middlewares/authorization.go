package middlewares

import (
	"github.com/shrinex/shield-web/pattern"
	"github.com/shrinex/shield/security"
	"log"
	"net/http"
	"net/http/httputil"
)

type (
	AuthorizationOption func(*AuthorizationMiddleware)

	AuthorizationMiddleware struct {
		mode     int
		subject  security.Subject
		registry *pattern.RouteRegistry
	}
)

const (
	affirmative = iota
	unanimous
)

func NewAuthorizationMiddleware(subject security.Subject,
	registry *pattern.RouteRegistry, opts ...AuthorizationOption) *AuthorizationMiddleware {
	m := &AuthorizationMiddleware{subject: subject, registry: registry}

	for _, f := range opts {
		f(m)
	}

	return m
}

func (m *AuthorizationMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(m.registry.Mappings) == 0 {
			next(w, r)
			return
		}

		var deny bool
		if m.mode == affirmative {
			deny = m.affirmative(r)
		} else {
			deny = m.unanimous(r)
		}

		if deny {
			forbidden(w, r)
			return
		}

		next(w, r)
	}
}

func (m *AuthorizationMiddleware) unanimous(r *http.Request) bool {
	for _, mapping := range m.registry.Mappings {
		if mapping.Matcher.Matches(r) {
			if !mapping.Predicate(r, m.subject) {
				return true
			}
		}
	}

	return false
}

func (m *AuthorizationMiddleware) affirmative(r *http.Request) bool {
	deny := 0
	for _, mapping := range m.registry.Mappings {
		if mapping.Matcher.Matches(r) {
			if mapping.Predicate(r, m.subject) {
				return false
			}
			deny += 1
		}
	}

	return deny > 0
}

func detailDenyLog(r *http.Request) {
	// discard dump error, only for debug purpose
	details, _ := httputil.DumpRequest(r, true)
	log.Printf("forbidden: %+v\n", string(details))
}

func forbidden(w http.ResponseWriter, r *http.Request) {
	// log first
	detailDenyLog(r)

	// if user not setting HTTP header, we set header with 403
	w.WriteHeader(http.StatusForbidden)
}

func WithUnanimousMode() AuthorizationOption {
	return func(m *AuthorizationMiddleware) {
		m.mode = unanimous
	}
}
