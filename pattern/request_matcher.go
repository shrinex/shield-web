package pattern

import (
	"net/http"
)

type (
	RequestMatcher interface {
		Matches(*http.Request) bool
	}

	RequestMatcherOption func(*antRequestMatcher)

	antRequestMatcher struct {
		httpMethod string
		pattern    string
		matcher    Matcher
	}
)

const patternMatchAll = "/**"

var _ RequestMatcher = (*antRequestMatcher)(nil)

func NewAntRequestMatcher(pattern string, opts ...RequestMatcherOption) RequestMatcher {
	if pattern == "**" {
		pattern = patternMatchAll
	}

	m := &antRequestMatcher{
		pattern: pattern,
		matcher: NewMatcher(),
	}

	for _, f := range opts {
		f(m)
	}

	return m
}

func (m *antRequestMatcher) Matches(r *http.Request) bool {
	if len(m.httpMethod) > 0 && m.httpMethod != r.Method {
		return false
	}

	if m.pattern == patternMatchAll {
		return true
	}

	return m.matcher.Matches(m.pattern, r.URL.Path)
}

func WithHttpMethod(method string) RequestMatcherOption {
	return func(matcher *antRequestMatcher) {
		matcher.httpMethod = method
	}
}
