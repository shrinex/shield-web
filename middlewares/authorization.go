package middlewares

import (
	"encoding/json"
	"github.com/shrinex/shield-web/pattern"
	"github.com/shrinex/shield/security"
	"log"
	"net/http"
	"net/http/httputil"
)

type (
	AuthzMode int

	AuthzOption func(*AuthzMiddleware)

	AuthzMiddleware struct {
		mode             AuthzMode
		subject          security.Subject
		registry         *pattern.RouteRegistry
		forbiddenHandler func(http.ResponseWriter, *http.Request)
	}
)

const (
	// Affirmative 有一个满足就可以
	Affirmative AuthzMode = iota
	// Unanimous 全部满足才可以
	Unanimous
)

func NewAuthzMiddleware(subject security.Subject,
	registry *pattern.RouteRegistry, opts ...AuthzOption) *AuthzMiddleware {
	m := &AuthzMiddleware{subject: subject, registry: registry}

	for _, f := range opts {
		f(m)
	}

	if m.forbiddenHandler == nil {
		m.forbiddenHandler = defaultForbiddenHandler
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
		if m.mode == Affirmative {
			deny = m.affirmative(r)
		} else {
			deny = m.unanimous(r)
		}

		if deny {
			m.forbiddenHandler(w, r)
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
				deny += 1 // nolint
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

func defaultForbiddenHandler(w http.ResponseWriter, r *http.Request) {
	// log first
	detailDenyLog(r)

	// if user not setting HTTP header, we set header with 403
	w.WriteHeader(http.StatusForbidden)

	bytes, err := json.Marshal(struct {
		Code    int32  `json:"code"`    // 错误码
		Message string `json:"message"` // 错误信息
	}{
		Code:    http.StatusForbidden,
		Message: "权限不足",
	})
	if err != nil {
		log.Printf("json marshal failed: %s\n", err.Error())
		return
	}

	_, err = w.Write(bytes)
	if err != nil {
		log.Printf("write body failed: %s\n", err.Error())
		return
	}
}

func WithAuthzMode(mode AuthzMode) AuthzOption {
	return func(m *AuthzMiddleware) {
		m.mode = mode
	}
}

func WithForbiddenHandler(handler func(http.ResponseWriter, *http.Request)) AuthzOption {
	return func(m *AuthzMiddleware) {
		m.forbiddenHandler = handler
	}
}

func WithAffirmativeMode() AuthzOption {
	return WithAuthzMode(Affirmative)
}

func WithUnanimousMode() AuthzOption {
	return WithAuthzMode(Unanimous)
}
