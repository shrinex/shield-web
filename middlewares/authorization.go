package middlewares

import (
	"github.com/shrinex/shield-web/pattern"
	"github.com/shrinex/shield/security"
	"log"
	"net/http"
	"net/http/httputil"
)

type (
	AuthorizationMiddleware struct {
		subject  security.Subject
		registry *pattern.RouteRegistry
	}
)

func NewAuthorizationMiddleware(subject security.Subject,
	registry *pattern.RouteRegistry) *AuthorizationMiddleware {
	return &AuthorizationMiddleware{subject: subject, registry: registry}
}

func (m *AuthorizationMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(m.registry.Mappings) == 0 {
			next(w, r)
			return
		}

		match, pass := m.matchAndPass(r)
		if !match || pass {
			next(w, r)
			return
		}

		forbidden(w, r)
	}
}

func (m *AuthorizationMiddleware) matchAndPass(r *http.Request) (match bool, pass bool) {
	for _, mapping := range m.registry.Mappings {
		if mapping.Matcher.Matches(r) {
			match = true
			if mapping.Predicate(r.Context(), m.subject) {
				pass = true
				return
			}
		}
	}

	return
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
