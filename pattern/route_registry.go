package pattern

import (
	"github.com/shrinex/shield/authz"
	"github.com/shrinex/shield/security"
	"net/http"
)

type (
	Predicate func(*http.Request, security.Subject) bool

	URLMapping struct {
		Predicate Predicate
		Includes  []RouteMatcher
		Excludes  []RouteMatcher
	}

	RouteRegistry struct {
		Mappings []URLMapping
		Includes []RouteMatcher
		Excludes []RouteMatcher
	}
)

func NewRouteRegistry() *RouteRegistry {
	return &RouteRegistry{Mappings: make([]URLMapping, 0)}
}

func (r *RouteRegistry) RouteMatches(method string, patterns ...string) *RouteRegistry {
	for _, pattern := range patterns {
		r.Includes = append(r.Includes, NewRouteMatcher(pattern, WithHttpMethod(method)))
	}
	return r
}

func (r *RouteRegistry) AntMatches(patterns ...string) *RouteRegistry {
	for _, pattern := range patterns {
		r.Includes = append(r.Includes, NewRouteMatcher(pattern))
	}
	return r
}

func (r *RouteRegistry) RouteExcludes(method string, patterns ...string) *RouteRegistry {
	for _, pattern := range patterns {
		r.Excludes = append(r.Excludes, NewRouteMatcher(pattern, WithHttpMethod(method)))
	}
	return r
}

func (r *RouteRegistry) AntExcludes(patterns ...string) *RouteRegistry {
	for _, pattern := range patterns {
		r.Excludes = append(r.Excludes, NewRouteMatcher(pattern))
	}
	return r
}

func (r *RouteRegistry) AnyRequests() *RouteRegistry {
	return r.AntMatches(MatchAll)
}

func (r *RouteRegistry) That(predicate Predicate) *RouteRegistry {
	if len(r.Includes) == 0 {
		panic("call AntMatches/RouteMatches(...) first")
	}
	r.Mappings = append(r.Mappings, URLMapping{
		Predicate: predicate,
		Includes:  r.Includes,
		Excludes:  r.Excludes,
	})
	r.Includes = nil
	r.Excludes = nil
	return r
}

func (r *RouteRegistry) And() *RouteRegistry {
	return r
}

func (r *RouteRegistry) DenyAll() *RouteRegistry {
	return r.That(func(*http.Request, security.Subject) bool {
		return false
	})
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
		return subject.HasRole(r.Context(), role)
	})
}

func (r *RouteRegistry) HasRoleFunc(fn func(*http.Request, security.Subject) authz.Role) *RouteRegistry {
	return r.That(func(r *http.Request, subject security.Subject) bool {
		return subject.HasRole(r.Context(), fn(r, subject))
	})
}

func (r *RouteRegistry) HasAnyRole(roles ...authz.Role) *RouteRegistry {
	return r.That(func(r *http.Request, subject security.Subject) bool {
		return subject.HasAnyRole(r.Context(), roles...)
	})
}

func (r *RouteRegistry) HasAnyRoleFunc(fn func(*http.Request, security.Subject) []authz.Role) *RouteRegistry {
	return r.That(func(r *http.Request, subject security.Subject) bool {
		return subject.HasAnyRole(r.Context(), fn(r, subject)...)
	})
}

func (r *RouteRegistry) HasAllRole(roles ...authz.Role) *RouteRegistry {
	return r.That(func(r *http.Request, subject security.Subject) bool {
		return subject.HasAllRole(r.Context(), roles...)
	})
}

func (r *RouteRegistry) HasAllRoleFunc(fn func(*http.Request, security.Subject) []authz.Role) *RouteRegistry {
	return r.That(func(r *http.Request, subject security.Subject) bool {
		return subject.HasAllRole(r.Context(), fn(r, subject)...)
	})
}

func (r *RouteRegistry) HasAuthority(authority authz.Authority) *RouteRegistry {
	return r.That(func(r *http.Request, subject security.Subject) bool {
		return subject.HasAuthority(r.Context(), authority)
	})
}

func (r *RouteRegistry) HasAuthorityFunc(fn func(*http.Request, security.Subject) authz.Authority) *RouteRegistry {
	return r.That(func(r *http.Request, subject security.Subject) bool {
		return subject.HasAuthority(r.Context(), fn(r, subject))
	})
}

func (r *RouteRegistry) HasAnyAuthority(authorities ...authz.Authority) *RouteRegistry {
	return r.That(func(r *http.Request, subject security.Subject) bool {
		return subject.HasAnyAuthority(r.Context(), authorities...)
	})
}

func (r *RouteRegistry) HasAnyAuthorityFunc(fn func(*http.Request, security.Subject) []authz.Authority) *RouteRegistry {
	return r.That(func(r *http.Request, subject security.Subject) bool {
		return subject.HasAnyAuthority(r.Context(), fn(r, subject)...)
	})
}

func (r *RouteRegistry) HasAllAuthority(authorities ...authz.Authority) *RouteRegistry {
	return r.That(func(r *http.Request, subject security.Subject) bool {
		return subject.HasAllAuthority(r.Context(), authorities...)
	})
}

func (r *RouteRegistry) HasAllAuthorityFunc(fn func(*http.Request, security.Subject) []authz.Authority) *RouteRegistry {
	return r.That(func(r *http.Request, subject security.Subject) bool {
		return subject.HasAllAuthority(r.Context(), fn(r, subject)...)
	})
}
