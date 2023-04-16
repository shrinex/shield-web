package middlewares

import (
	"github.com/shrinex/shield-web/pattern"
	"github.com/shrinex/shield/security"
	"log"
	"net/http"
	"net/http/httputil"
)

type (
	AuthzOption func(*AuthzMiddleware)

	AuthzMiddleware struct {
		mode     int
		subject  security.Subject
		registry *pattern.RouteRegistry
	}
)

const (
	// unanimous 全部满足才可以
	unanimous = iota
	// affirmative 有一个满足就可以
	affirmative
)

func NewAuthzMiddleware(subject security.Subject,
	registry *pattern.RouteRegistry, opts ...AuthzOption) *AuthzMiddleware {
	m := &AuthzMiddleware{subject: subject, registry: registry}

	for _, f := range opts {
		f(m)
	}

	return m
}

func (m *AuthzMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(m.registry.Mappings) == 0 {
			next(w, r)
			return
		}

		var deny bool
		if m.mode == unanimous {
			deny = m.unanimous(r)
		} else {
			deny = m.affirmative(r)
		}

		if deny {
			forbidden(w, r)
			return
		}

		next(w, r)
	}
}

func (m *AuthzMiddleware) unanimous(r *http.Request) bool {
	for _, mapping := range m.registry.Mappings {
		if m.excluded(mapping.Excludes, r) {
			return false
		}

		for _, matcher := range mapping.Includes {
			if matcher.Matches(r) {
				if !mapping.Predicate(r, m.subject) {
					return true
				}
			}
		}
	}

	return false
}

func (m *AuthzMiddleware) affirmative(r *http.Request) bool {
	deny := 0
	for _, mapping := range m.registry.Mappings {
		if m.excluded(mapping.Excludes, r) {
			return false
		}

		for _, matcher := range mapping.Includes {
			if matcher.Matches(r) {
				if mapping.Predicate(r, m.subject) {
					return false
				}
				deny += 1
			}
		}
	}

	return deny > 0
}

func (m *AuthzMiddleware) excluded(excludes []pattern.RouteMatcher, r *http.Request) bool {
	if len(excludes) == 0 {
		return false
	}

	for _, matcher := range excludes {
		if matcher.Matches(r) {
			return true
		}
	}

	return false
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

func WithAffirmativeMode() AuthzOption {
	return func(m *AuthzMiddleware) {
		m.mode = affirmative
	}
}
