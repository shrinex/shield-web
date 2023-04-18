package middlewares

import (
	"github.com/shrinex/shield/security"
	"github.com/shrinex/shield/semgt"
	"net/http"
)

type (
	SessionMiddleware struct {
		subject security.Subject
	}

	sessionResponseWriter struct {
		http.ResponseWriter
		request *http.Request
		session semgt.Session
		written bool
	}
)

func NewSessionMiddleware(subject security.Subject) *SessionMiddleware {
	return &SessionMiddleware{subject: subject}
}

func (m *SessionMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := m.subject.Session(r.Context())
		if err != nil {
			next(w, r)
			return
		}

		sw := &sessionResponseWriter{
			ResponseWriter: w,
			request:        r,
			session:        s,
		}

		next(w, r)

		if !sw.written {
			_ = s.Flush(r.Context())
		}
	}
}

func (sw *sessionResponseWriter) Write(b []byte) (int, error) {
	if !sw.written {
		_ = sw.session.Flush(sw.request.Context())
		sw.written = true
	}

	return sw.ResponseWriter.Write(b)
}

func (sw *sessionResponseWriter) WriteHeader(code int) {
	if !sw.written {
		_ = sw.session.Flush(sw.request.Context())
		sw.written = true
	}

	sw.ResponseWriter.WriteHeader(code)
}

func (sw *sessionResponseWriter) Unwrap() http.ResponseWriter {
	return sw.ResponseWriter
}
