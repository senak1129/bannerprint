// Package api 实现 HTTP 契约层（对应 spec §4）。
//
// 这一层只做四件事：路由、校验、限流/限额、错误映射。
// 识别逻辑一律委托给 engine —— 保证同一份识别逻辑既可通过 HTTP 使用，
// 也可被单元测试直接调用（不启动服务器、不占端口）。
package api

import (
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/bannerprint/bannerprint/internal/config"
	"github.com/bannerprint/bannerprint/internal/engine"
	"github.com/bannerprint/bannerprint/internal/rules"
)

// Server 是 HTTP 服务的依赖容器。
type Server struct {
	cfg     config.Config
	eng     *engine.Engine
	log     *slog.Logger
	version string
	start   time.Time

	// ready 表示「规则已加载、引擎可用」。它由启动流程决定，
	// /health 直接读它，而不是无条件返回 200 —— 健康检查必须反映真实状态。
	ready atomic.Bool

	rules rules.Stats
}

// New 构造服务。调用前必须已完成规则加载；规则加载失败时不应构造 Server。
func New(cfg config.Config, eng *engine.Engine, stats rules.Stats, log *slog.Logger, version string) *Server {
	s := &Server{
		cfg:     cfg,
		eng:     eng,
		log:     log,
		version: version,
		start:   time.Now(),
		rules:   stats,
	}
	s.ready.Store(true)
	return s
}

// Handler 返回装配好中间件的根 handler。
//
// 中间件顺序（外→内）：
//
//	recover → request-id → access-log → auth → route
//
// recover 必须在最外层：任何一层的 panic 都要变成 500 JSON，而不是断开连接。
func (s *Server) Handler() http.Handler {
	var h http.Handler = http.HandlerFunc(s.route)
	h = s.authMiddleware(h)
	h = s.accessLogMiddleware(h)
	h = s.requestIDMiddleware(h)
	h = s.recoverMiddleware(h)
	return h
}

// route 是显式路由表。
//
// 刻意不使用 ServeMux 的方法路由：本服务只有两条路径，手写 switch 能精确控制
// 405/404 的 JSON 错误体（ServeMux 默认返回纯文本），也更容易审计「暴露了哪些入口」。
func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/fingerprint":
		s.handleFingerprint(w, r)
	case "/health":
		s.handleHealth(w, r)
	default:
		writeError(w, r, http.StatusNotFound, "not_found", "unknown route")
	}
}
