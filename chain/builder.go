package chain

import (
	ant "github.com/shrinex/shield-web/pattern"
	"github.com/shrinex/shield/security"
	"net/http"
	"sort"
)

type (
	Middleware = func(http.HandlerFunc) http.HandlerFunc

	Configurer = SecurityConfigurer[Middleware, *Builder]

	Builder struct {
		subject security.Subject
		chain   []Middleware
		cfgs    []Configurer
	}
)

// NewBuilder returns a newly created chain builder
// Do not retain reference of returned object, or any
// other objects created by this Builder, like AuthcConfigurer
func NewBuilder() *Builder {
	return &Builder{}
}

func (b *Builder) Subject() *SubjectConfigurer {
	return b.apply(&SubjectConfigurer{builder: b}).(*SubjectConfigurer)
}

func (b *Builder) BearerAuth() *AuthcConfigurer {
	return b.apply(&AuthcConfigurer{builder: b}).(*AuthcConfigurer)
}

func (b *Builder) SessionManagement() *SessionManagementConfigurer {
	return b.apply(&SessionManagementConfigurer{builder: b}).(*SessionManagementConfigurer)
}

func (b *Builder) AuthorizeRequests() *AuthzConfigurer {
	return b.apply(&AuthzConfigurer{
		builder:  b,
		registry: ant.NewRouteRegistry(),
	}).(*AuthzConfigurer)
}

func (b *Builder) Build() Middleware {
	// order is important here
	sort.Sort(byOrder(b.cfgs))
	for _, cfg := range b.cfgs {
		cfg.Configure(b)
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		for i := range b.chain {
			next = b.chain[len(b.chain)-1-i](next)
		}

		return next
	}
}

func (b *Builder) apply(configurer Configurer) Configurer {
	b.cfgs = append(b.cfgs, configurer)
	return configurer
}

type byOrder []Configurer

func (s byOrder) Len() int           { return len(s) }
func (s byOrder) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s byOrder) Less(i, j int) bool { return s[i].Order() < s[j].Order() }
