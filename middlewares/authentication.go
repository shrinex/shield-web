package middlewares

import (
	"encoding/json"
	"errors"
	ant "github.com/shrinex/shield-web/pattern"
	"github.com/shrinex/shield/authc"
	"github.com/shrinex/shield/security"
	"github.com/shrinex/shield/semgt"
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
	AuthcOption func(*AuthcMiddleware)

	AuthcMiddleware struct {
		subject             security.Subject
		matcher             ant.Matcher
		includePatterns     []string
		excludePatterns     []string
		unauthorizedHandler func(http.ResponseWriter, *http.Request, error)
	}
)

func NewAuthcMiddleware(subject security.Subject, opts ...AuthcOption) *AuthcMiddleware {
	m := &AuthcMiddleware{subject: subject}

	for _, f := range opts {
		f(m)
	}

	if m.matcher == nil {
		m.matcher = ant.NewMatcher()
	}

	if m.unauthorizedHandler == nil {
		m.unauthorizedHandler = defaultUnauthorizedHandler
	}

	return m
}

func (m *AuthcMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if m.shouldSkip(r) {
			next(w, r)
			return
		}

		m.bearerAuth(w, r, next)
	}
}

func (m *AuthcMiddleware) shouldSkip(r *http.Request) bool {
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

func (m *AuthcMiddleware) bearerAuth(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	value, err := parseTokenValue(r)
	if err != nil {
		m.unauthorizedHandler(w, r, err)
		return
	}

	token := authc.NewBearerToken(value)
	ctx, err := m.subject.Login(r.Context(), token)
	if err != nil {
		m.unauthorizedHandler(w, r, err)
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

func defaultUnauthorizedHandler(w http.ResponseWriter, r *http.Request, err error) {
	// log first
	detailAuthLog(r, err.Error())

	// if user not setting HTTP header, we set header with 401
	w.WriteHeader(http.StatusUnauthorized)

	bytes, err := json.Marshal(struct {
		Code    int32  `json:"code"`    // 错误码
		Message string `json:"message"` // 错误信息
	}{
		Code:    http.StatusUnauthorized,
		Message: evalMessage(err),
	})
	if err != nil {
		log.Printf("json marshal failed: %s\n", err.Error())
		return
	}

	_, err = w.Write(bytes)
	if err != nil {
		log.Printf("write body failed: %s\n", err.Error())
		return
	}
}

func evalMessage(err error) string {
	if errors.Is(err, authc.ErrInvalidToken) {
		return "token格式不正确"
	}

	if errors.Is(err, authc.ErrUnauthenticated) {
		return "请先登录"
	}

	if errors.Is(err, semgt.ErrExpired) {
		return "会话已过期，请重新登录"
	}

	if errors.Is(err, semgt.ErrReplaced) {
		return "当前账号已在其它设备登录"
	}

	if errors.Is(err, semgt.ErrOverflow) {
		return "会话已超限，请重新登录"
	}

	return err.Error()
}

func WithMatcher(matcher ant.Matcher) AuthcOption {
	return func(m *AuthcMiddleware) {
		m.matcher = matcher
	}
}

func WithUnauthorizedHandler(handler func(http.ResponseWriter, *http.Request, error)) AuthcOption {
	return func(m *AuthcMiddleware) {
		m.unauthorizedHandler = handler
	}
}

func WithPatterns(patterns ...string) AuthcOption {
	return func(m *AuthcMiddleware) {
		m.includePatterns = append(m.includePatterns, patterns...)
	}
}

func WithExcludePatterns(patterns ...string) AuthcOption {
	return func(m *AuthcMiddleware) {
		m.excludePatterns = append(m.excludePatterns, patterns...)
	}
}
