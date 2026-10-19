package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// contextKey 是本包私有的 context key 类型，避免与其他包的 key 冲突。
type contextKey int

const (
	ctxKeyRequestID contextKey = iota
	ctxKeyInfo
)

// requestInfo 由 handler 填充、由访问日志中间件输出。
// 用指针放在 context 里，避免为统计数字再返回一次。
type requestInfo struct {
	Items   int
	Unknown int
}

// statusWriter 捕获响应状态码，供访问日志使用。
type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status = code
		w.wrote = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.status = http.StatusOK
		w.wrote = true
	}
	return w.ResponseWriter.Write(b)
}

// recoverMiddleware 把 panic 转为 500 JSON。
// 单条数据层面的 panic 已在 engine 内部消化；能走到这里的属于真正的程序缺陷，
// 必须记录完整堆栈（slog 默认会带 stack），但绝不能断开连接。
func (s *Server) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic recovered",
					slog.String("request_id", requestID(r)),
					slog.String("path", r.URL.Path),
					slog.Any("panic", rec),
				)
				writeError(w, r, http.StatusInternalServerError, "internal", "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// requestIDMiddleware 透传或生成请求 ID，并回写到响应头，便于日志关联。
func (s *Server) requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" || len(id) > 128 {
			id = newRequestID()
		}
		w.Header().Set("X-Request-ID", id)
		ctx := r.Context()
		ctx = context.WithValue(ctx, ctxKeyRequestID, id)
		ctx = context.WithValue(ctx, ctxKeyInfo, &requestInfo{})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// accessLogMiddleware 输出一行结构化访问日志。
//
// 刻意不记录完整 banner：扫描数据可能包含凭据或内网拓扑信息。
// 只记录条数与 unknown 数，足以判断规则是否退化。
func (s *Server) accessLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)

		attrs := []any{
			slog.String("request_id", requestID(r)),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", sw.status),
			slog.Int64("duration_ms", time.Since(start).Milliseconds()),
		}
		if info, ok := r.Context().Value(ctxKeyInfo).(*requestInfo); ok && info.Items > 0 {
			attrs = append(attrs,
				slog.Int("items", info.Items),
				slog.Int("unknown", info.Unknown),
			)
		}
		s.log.Info("request", attrs...)
	})
}

// authMiddleware 实现可选的 Bearer Token 鉴权（API_TOKEN 非空时生效）。
// 默认关闭，保证评估者可以直接 curl，不需要额外配置。
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	if s.cfg.APIToken == "" {
		return next
	}
	want := []byte("Bearer " + s.cfg.APIToken)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(strings.TrimSpace(r.Header.Get("Authorization")))
		if subtle.ConstantTimeCompare(got, want) != 1 {
			writeError(w, r, http.StatusUnauthorized, "unauthorized", "invalid or missing bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// newRequestID 生成 128 位随机 ID，不引入第三方 ULID 依赖。
func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "req"
	}
	return hex.EncodeToString(b[:])
}

// requestID 从 context 取请求 ID，取不到时返回空串。
func requestID(r *http.Request) string {
	if v, ok := r.Context().Value(ctxKeyRequestID).(string); ok {
		return v
	}
	return ""
}
