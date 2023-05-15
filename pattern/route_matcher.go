package pattern

import (
	"net/http"
)

type (
	RouteMatcher interface {
		Matches(*http.Request) bool
	}

	RouteMatcherOption func(*antRouteMatcher)

	antRouteMatcher struct {
		httpMethod string
		pattern    string
		matcher    Matcher
	}
)

const MatchAll = "/**"

var _ RouteMatcher = (*antRouteMatcher)(nil)

func NewRouteMatcher(pattern string, opts ...RouteMatcherOption) RouteMatcher {
	if pattern == "**" {
		pattern = MatchAll
	}

	m := &antRouteMatcher{
		pattern: pattern,
		matcher: NewMatcher(),
	}

	for _, f := range opts {
		f(m)
	}

	return m
}

func (m *antRouteMatcher) Matches(r *http.Request) bool {
	if len(m.httpMethod) > 0 && m.httpMethod != r.Method {
		return false
	}

	if m.pattern == MatchAll {
		return true
	}

	return m.matcher.Matches(m.pattern, r.URL.Path)
}

func WithHTTPMethod(method string) RouteMatcherOption {
	return func(matcher *antRouteMatcher) {
		matcher.httpMethod = method
	}
}
