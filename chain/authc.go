package chain

import (
	"github.com/shrinex/shield-web/middlewares"
	ant "github.com/shrinex/shield-web/pattern"
)

type (
	AuthcConfigurer struct {
		builder  *Builder
		includes []string
		excludes []string
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

func (c *AuthcConfigurer) And() *Builder {
	return c.builder
}

func (c *AuthcConfigurer) Configure(builder *Builder) {
	if builder.subject == nil {
		panic("call Subject() first")
	}
	builder.chain = append(builder.chain,
		middlewares.NewAuthcMiddleware(
			builder.subject,
			middlewares.WithPatterns(c.includes...),
			middlewares.WithExcludePatterns(c.excludes...),
		).Handle)
}
