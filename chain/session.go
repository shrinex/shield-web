package chain

import (
	"github.com/shrinex/shield-web/middlewares"
)

type (
	SessionManagementConfigurer struct {
		builder *Builder
	}
)

var _ Configurer = (*SessionManagementConfigurer)(nil)

func (c *SessionManagementConfigurer) And() *Builder {
	return c.builder
}

func (c *SessionManagementConfigurer) Order() int {
	return 20
}

func (c *SessionManagementConfigurer) Configure(builder *Builder) {
	if builder.subject == nil {
		panic("call Builder.Subject() first")
	}
	builder.chain = append(builder.chain,
		middlewares.NewSessionMiddleware(
			builder.subject,
		).Handle,
	)
}
