package chain

import (
	"github.com/shrinex/shield-web/middlewares"
	ant "github.com/shrinex/shield-web/pattern"
	"net/http"
)

type (
	AuthcConfigurer struct {
		builder  *Builder
		includes []string
		excludes []string
		matcher  ant.Matcher
		handler  func(http.ResponseWriter, *http.Request, error)
	}
)

var _ Configurer = (*AuthcConfigurer)(nil)

func (c *AuthcConfigurer) AntMatches(patterns ...string) *AuthcConfigurer {
	c.includes = append(c.includes, patterns...)
	return c
}

func (c *AuthcConfigurer) AnyRequests() *AuthcConfigurer {
	c.AntMatches(ant.MatchAll)
	return c
}

func (c *AuthcConfigurer) AntExcludes(patterns ...string) *AuthcConfigurer {
	c.excludes = append(c.excludes, patterns...)
	return c
}

func (c *AuthcConfigurer) Use(matcher ant.Matcher) *AuthcConfigurer {
	c.matcher = matcher
	return c
}

func (c *AuthcConfigurer) WhenUnauthorized(handler func(http.ResponseWriter, *http.Request, error)) *AuthcConfigurer {
	c.handler = handler
	return c
}

func (c *AuthcConfigurer) And() *Builder {
	return c.builder
}

func (c *AuthcConfigurer) Order() int {
	return 10
}

func (c *AuthcConfigurer) Configure(builder *Builder) {
	if builder.subject == nil {
		panic("call Builder.Subject() first")
	}
	builder.chain = append(builder.chain,
		middlewares.NewAuthcMiddleware(
			builder.subject,
			middlewares.WithMatcher(c.matcher),
			middlewares.WithPatterns(c.includes...),
			middlewares.WithExcludePatterns(c.excludes...),
			middlewares.WithUnauthorizedHandler(c.handler),
		).Handle)
}
