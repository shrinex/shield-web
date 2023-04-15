package middlewares

import (
	ant "github.com/shrinex/shield-web/pattern"
	"github.com/shrinex/shield/authc"
	"github.com/shrinex/shield/security"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"
)

const (
	bearer              = "Bearer "
	authorizationHeader = "Authorization"
)

type (
	AuthenticationOption func(*AuthenticationMiddleware)

	AuthenticationMiddleware struct {
		subject         security.Subject
		matcher         ant.Matcher
		includePatterns []string
		excludePatterns []string
	}
)

func NewAuthenticationMiddleware(subject security.Subject, opts ...AuthenticationOption) *AuthenticationMiddleware {
	m := &AuthenticationMiddleware{subject: subject}

	for _, f := range opts {
		f(m)
	}

	if m.matcher == nil {
		m.matcher = ant.NewMatcher()
	}

	return m
}

func (m *AuthenticationMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if m.shouldSkip(r) {
			next(w, r)
			return
		}

		m.bearerAuth(w, r, next)
	}
}

func (m *AuthenticationMiddleware) shouldSkip(r *http.Request) bool {
	if len(m.excludePatterns) > 0 {
		for _, pattern := range m.excludePatterns {
			if m.matcher.Matches(pattern, r.URL.Path) {
				return true
			}
		}
	}

	if len(m.includePatterns) == 0 {
		return false
	}

	for _, pattern := range m.includePatterns {
		if m.matcher.Matches(pattern, r.URL.Path) {
			return false
		}
	}

	return true
}

func (m *AuthenticationMiddleware) bearerAuth(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	value, err := parseTokenValue(r)
	if err != nil {
		unauthorized(w, r, err)
		return
	}

	token := authc.NewBearerToken(value)
	ctx, err := m.subject.Login(r.Context(), token)
	if err != nil {
		unauthorized(w, r, err)
		return
	}

	next(w, r.WithContext(ctx))
}

func parseTokenValue(r *http.Request) (string, error) {
	val := r.Header.Get(authorizationHeader)
	if !strings.HasPrefix(val, bearer) {
		return "", authc.ErrInvalidToken
	}

	token := strings.TrimPrefix(val, bearer)
	if len(token) == 0 {
		return "", authc.ErrInvalidToken
	}

	return token, nil
}

func detailAuthLog(r *http.Request, reason string) {
	// discard dump error, only for debug purpose
	details, _ := httputil.DumpRequest(r, true)
	log.Printf("authorize failed: %s\n=> %+v\n", reason, string(details))
}

func unauthorized(w http.ResponseWriter, r *http.Request, err error) {
	// log first
	detailAuthLog(r, err.Error())

	// if user not setting HTTP header, we set header with 401
	w.WriteHeader(http.StatusUnauthorized)
}

func WithMatcher(matcher ant.Matcher) AuthenticationOption {
	return func(m *AuthenticationMiddleware) {
		m.matcher = matcher
	}
}

func WithPatterns(pattern string, patterns ...string) AuthenticationOption {
	return func(m *AuthenticationMiddleware) {
		m.includePatterns = append(m.includePatterns, pattern)
		m.includePatterns = append(m.includePatterns, patterns...)
	}
}

func WithExcludePatterns(pattern string, patterns ...string) AuthenticationOption {
	return func(m *AuthenticationMiddleware) {
		m.excludePatterns = append(m.excludePatterns, pattern)
		m.excludePatterns = append(m.excludePatterns, patterns...)
	}
}
