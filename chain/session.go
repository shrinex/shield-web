package chain

import (
	"github.com/shrinex/shield-web/middlewares"
	"github.com/shrinex/shield/security"
	"time"
)

type (
	SessionManagementConfigurer struct {
		builder        *Builder
		timeout        time.Duration
		timeoutSet     bool
		idleTimeout    time.Duration
		idleTimeoutSet bool
		concurrency    int
		concurrencySet bool
		newToken       func(any) string
		newTokenSet    bool
	}
)

var _ Configurer = (*SessionManagementConfigurer)(nil)

func (c *SessionManagementConfigurer) Timeout(timeout time.Duration) *SessionManagementConfigurer {
	c.timeout = timeout
	c.timeoutSet = true
	return c
}

func (c *SessionManagementConfigurer) IdleTimeout(idleTimeout time.Duration) *SessionManagementConfigurer {
	c.idleTimeout = idleTimeout
	c.idleTimeoutSet = true
	return c
}

func (c *SessionManagementConfigurer) Concurrency(concurrency int) *SessionManagementConfigurer {
	c.concurrency = concurrency
	c.concurrencySet = true
	return c
}

func (c *SessionManagementConfigurer) NewToken(newToken func(any) string) *SessionManagementConfigurer {
	c.newToken = newToken
	c.newTokenSet = true
	return c
}

func (c *SessionManagementConfigurer) And() *Builder {
	return c.builder
}

func (c *SessionManagementConfigurer) Configure(builder *Builder) {
	if builder.subject == nil {
		panic("call Subject() first")
	}

	if c.timeoutSet {
		security.GetGlobalOptions().Timeout = c.timeout
	}
	if c.newTokenSet {
		security.GetGlobalOptions().NewToken = c.newToken
	}
	if c.concurrencySet {
		security.GetGlobalOptions().Concurrency = c.concurrency
	}
	if c.idleTimeoutSet {
		security.GetGlobalOptions().IdleTimeout = c.idleTimeout
	}
	builder.chain = append(builder.chain,
		middlewares.NewSessionMiddleware(
			builder.subject,
		).Handle,
	)
}
