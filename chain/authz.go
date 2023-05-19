package chain

import (
	"github.com/shrinex/shield-web/middlewares"
	ant "github.com/shrinex/shield-web/pattern"
	"github.com/shrinex/shield/authz"
	"github.com/shrinex/shield/security"
	"net/http"
)

type (
	AuthzConfigurer struct {
		builder  *Builder
		registry *ant.RouteRegistry
		mode     middlewares.AuthzMode
		handler  func(http.ResponseWriter, *http.Request)
	}
)

var _ Configurer = (*AuthzConfigurer)(nil)

func (c *AuthzConfigurer) Use(registry *ant.RouteRegistry) *AuthzConfigurer {
	if len(c.registry.Mappings) > 0 ||
		len(c.registry.Includes) > 0 ||
		len(c.registry.Excludes) > 0 {
		panic("call AuthzConfigurer.Use() first")
	}
	c.registry = registry
	return c
}

func (c *AuthzConfigurer) RouteMatches(method string, patterns ...string) *AuthzConfigurer {
	c.registry.RouteMatches(method, patterns...)
	return c
}

func (c *AuthzConfigurer) RouteExcludes(method string, patterns ...string) *AuthzConfigurer {
	c.registry.RouteExcludes(method, patterns...)
	return c
}

func (c *AuthzConfigurer) AntMatches(patterns ...string) *AuthzConfigurer {
	c.registry.AntMatches(patterns...)
	return c
}

func (c *AuthzConfigurer) AntExcludes(patterns ...string) *AuthzConfigurer {
	c.registry.AntExcludes(patterns...)
	return c
}

func (c *AuthzConfigurer) AnyRequests() *AuthzConfigurer {
	c.registry.AnyRequests()
	return c
}

func (c *AuthzConfigurer) That(predicate ant.Predicate) *AuthzConfigurer {
	c.registry.That(predicate)
	return c
}

func (c *AuthzConfigurer) DenyAll() *AuthzConfigurer {
	c.registry.DenyAll()
	return c
}

func (c *AuthzConfigurer) PermitAll() *AuthzConfigurer {
	c.registry.PermitAll()
	return c
}

func (c *AuthzConfigurer) Authenticated() *AuthzConfigurer {
	c.registry.Authenticated()
	return c
}

func (c *AuthzConfigurer) HasRole(role authz.Role) *AuthzConfigurer {
	c.registry.HasRole(role)
	return c
}

func (c *AuthzConfigurer) HasRoleFunc(fn func(*http.Request, security.Subject) authz.Role) *AuthzConfigurer {
	c.registry.HasRoleFunc(fn)
	return c
}

func (c *AuthzConfigurer) HasAnyRole(roles ...authz.Role) *AuthzConfigurer {
	c.registry.HasAnyRole(roles...)
	return c
}

func (c *AuthzConfigurer) HasAnyRoleFunc(fn func(*http.Request, security.Subject) []authz.Role) *AuthzConfigurer {
	c.registry.HasAnyRoleFunc(fn)
	return c
}

func (c *AuthzConfigurer) HasAllRole(roles ...authz.Role) *AuthzConfigurer {
	c.registry.HasAllRole(roles...)
	return c
}

func (c *AuthzConfigurer) HasAllRoleFunc(fn func(*http.Request, security.Subject) []authz.Role) *AuthzConfigurer {
	c.registry.HasAllRoleFunc(fn)
	return c
}

func (c *AuthzConfigurer) HasAuthority(authority authz.Authority) *AuthzConfigurer {
	c.registry.HasAuthority(authority)
	return c
}

func (c *AuthzConfigurer) HasAuthorityFunc(fn func(*http.Request, security.Subject) authz.Authority) *AuthzConfigurer {
	c.registry.HasAuthorityFunc(fn)
	return c
}

func (c *AuthzConfigurer) HasAnyAuthority(authorities ...authz.Authority) *AuthzConfigurer {
	c.registry.HasAnyAuthority(authorities...)
	return c
}

func (c *AuthzConfigurer) HasAnyAuthorityFunc(fn func(*http.Request, security.Subject) []authz.Authority) *AuthzConfigurer {
	c.registry.HasAnyAuthorityFunc(fn)
	return c
}

func (c *AuthzConfigurer) HasAllAuthority(authorities ...authz.Authority) *AuthzConfigurer {
	c.registry.HasAllAuthority(authorities...)
	return c
}

func (c *AuthzConfigurer) HasAllAuthorityFunc(fn func(*http.Request, security.Subject) []authz.Authority) *AuthzConfigurer {
	c.registry.HasAllAuthorityFunc(fn)
	return c
}

func (c *AuthzConfigurer) UnanimousMode() *AuthzConfigurer {
	c.mode = middlewares.Unanimous
	return c
}

func (c *AuthzConfigurer) AffirmativeMode() *AuthzConfigurer {
	c.mode = middlewares.Affirmative
	return c
}

func (c *AuthzConfigurer) WhenForbidden(handler func(http.ResponseWriter, *http.Request)) *AuthzConfigurer {
	c.handler = handler
	return c
}

func (c *AuthzConfigurer) And() *Builder {
	return c.builder
}

func (c *AuthzConfigurer) Order() int {
	return 30
}

func (c *AuthzConfigurer) Configure(builder *Builder) {
	if builder.subject == nil {
		panic("call Builder.Subject() first")
	}
	builder.chain = append(builder.chain,
		middlewares.NewAuthzMiddleware(
			builder.subject,
			middlewares.WithAuthzMode(c.mode),
			middlewares.WithRouteRegistry(c.registry),
			middlewares.WithForbiddenHandler(c.handler),
		).Handle)
}
