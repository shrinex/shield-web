package chain

import (
	"github.com/shrinex/shield/security"
)

type (
	SubjectConfigurer struct {
		builder *Builder
		subject security.Subject
	}
)

var _ Configurer = (*SubjectConfigurer)(nil)

func (c *SubjectConfigurer) Use(subject security.Subject) *SubjectConfigurer {
	c.subject = subject
	return c
}

func (c *SubjectConfigurer) And() *Builder {
	return c.builder
}

func (c *SubjectConfigurer) Order() int {
	return 0
}

func (c *SubjectConfigurer) Configure(builder *Builder) {
	builder.subject = c.subject
}
