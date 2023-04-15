package pattern

import (
	"context"
	"github.com/shrinex/shield/authz"
	"github.com/shrinex/shield/security"
)

type (
	Predicate func(context.Context, security.Subject) bool

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

func (r *RouteRegistry) Bypass() *RouteRegistry {
	return r.That(func(context.Context, security.Subject) bool {
		return true
	})
}

func (r *RouteRegistry) Authenticated() *RouteRegistry {
	return r.That(func(ctx context.Context, subject security.Subject) bool {
		return subject.Authenticated(ctx)
	})
}

func (r *RouteRegistry) HasRole(role authz.Role) *RouteRegistry {
	return r.That(func(ctx context.Context, subject security.Subject) bool {
		grant, err := subject.HasRole(ctx, role)
		if err != nil {
			return false
		}

		return grant
	})
}

func (r *RouteRegistry) HasAnyRole(roles ...authz.Role) *RouteRegistry {
	return r.That(func(ctx context.Context, subject security.Subject) bool {
		grant, err := subject.HasAnyRole(ctx, roles...)
		if err != nil {
			return false
		}

		return grant
	})
}

func (r *RouteRegistry) HasAllRole(roles ...authz.Role) *RouteRegistry {
	return r.That(func(ctx context.Context, subject security.Subject) bool {
		grant, err := subject.HasAllRole(ctx, roles...)
		if err != nil {
			return false
		}

		return grant
	})
}

func (r *RouteRegistry) HasAuthority(authority authz.Authority) *RouteRegistry {
	return r.That(func(ctx context.Context, subject security.Subject) bool {
		grant, err := subject.HasAuthority(ctx, authority)
		if err != nil {
			return false
		}

		return grant
	})
}

func (r *RouteRegistry) HasAnyAuthority(authorities ...authz.Authority) *RouteRegistry {
	return r.That(func(ctx context.Context, subject security.Subject) bool {
		grant, err := subject.HasAnyAuthority(ctx, authorities...)
		if err != nil {
			return false
		}

		return grant
	})
}

func (r *RouteRegistry) HasAllAuthority(authorities ...authz.Authority) *RouteRegistry {
	return r.That(func(ctx context.Context, subject security.Subject) bool {
		grant, err := subject.HasAllAuthority(ctx, authorities...)
		if err != nil {
			return false
		}

		return grant
	})
}
