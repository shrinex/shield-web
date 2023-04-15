package pattern

import (
	"github.com/shrinex/shield/authz"
	"github.com/shrinex/shield/security"
	"net/http"
)

type (
	Predicate func(*http.Request, security.Subject) bool

	UrlMapping struct {
		Matcher   RequestMatcher
		Predicate Predicate
	}

	RouteRegistry struct {
		Matcher  RequestMatcher
		Mappings []UrlMapping
	}
)

func NewRouteRegistry() *RouteRegistry {
	return &RouteRegistry{Mappings: make([]UrlMapping, 0)}
}

func (r *RouteRegistry) AntMatcher(pattern string, opts ...RequestMatcherOption) *RouteRegistry {
	r.Matcher = NewAntRequestMatcher(pattern, opts...)
	return r
}

func (r *RouteRegistry) AnyRequests() *RouteRegistry {
	return r.AntMatcher(patternMatchAll)
}

func (r *RouteRegistry) That(predicate Predicate) *RouteRegistry {
	if r.Matcher == nil {
		panic("call AntMatcher(...) first")
	}
	r.Mappings = append(r.Mappings, UrlMapping{
		Matcher:   r.Matcher,
		Predicate: predicate,
	})
	r.Matcher = nil
	return r
}

func (r *RouteRegistry) And() *RouteRegistry {
	return r
}

func (r *RouteRegistry) PermitAll() *RouteRegistry {
	return r.That(func(*http.Request, security.Subject) bool {
		return true
	})
}

func (r *RouteRegistry) Authenticated() *RouteRegistry {
	return r.That(func(r *http.Request, subject security.Subject) bool {
		return subject.Authenticated(r.Context())
	})
}

func (r *RouteRegistry) HasRole(role authz.Role) *RouteRegistry {
	return r.That(func(r *http.Request, subject security.Subject) bool {
		grant, err := subject.HasRole(r.Context(), role)
		if err != nil {
			return false
		}

		return grant
	})
}

func (r *RouteRegistry) HasAnyRole(roles ...authz.Role) *RouteRegistry {
	return r.That(func(r *http.Request, subject security.Subject) bool {
		grant, err := subject.HasAnyRole(r.Context(), roles...)
		if err != nil {
			return false
		}

		return grant
	})
}

func (r *RouteRegistry) HasAllRole(roles ...authz.Role) *RouteRegistry {
	return r.That(func(r *http.Request, subject security.Subject) bool {
		grant, err := subject.HasAllRole(r.Context(), roles...)
		if err != nil {
			return false
		}

		return grant
	})
}

func (r *RouteRegistry) HasAuthority(authority authz.Authority) *RouteRegistry {
	return r.That(func(r *http.Request, subject security.Subject) bool {
		grant, err := subject.HasAuthority(r.Context(), authority)
		if err != nil {
			return false
		}

		return grant
	})
}

func (r *RouteRegistry) HasAnyAuthority(authorities ...authz.Authority) *RouteRegistry {
	return r.That(func(r *http.Request, subject security.Subject) bool {
		grant, err := subject.HasAnyAuthority(r.Context(), authorities...)
		if err != nil {
			return false
		}

		return grant
	})
}

func (r *RouteRegistry) HasAllAuthority(authorities ...authz.Authority) *RouteRegistry {
	return r.That(func(r *http.Request, subject security.Subject) bool {
		grant, err := subject.HasAllAuthority(r.Context(), authorities...)
		if err != nil {
			return false
		}

		return grant
	})
}
