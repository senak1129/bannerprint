// Package obs 提供结构化日志。
//
// 设计要点（对应 spec §10.5）：
//   - 日志一律写 stdout，由容器运行时收集；错误也写 stdout，避免 stderr/stdout 双流交错；
//   - 默认 JSON 行格式，便于 `docker compose logs | jq`；
//   - info 级别**不打印完整 banner**：扫描数据可能包含口令、Token 等敏感内容。
package obs

import (
	"log/slog"
	"os"
	"strings"
)

// New 按配置构造 logger。level 非法时回退 info，format 非 "text" 时使用 JSON。
func New(level, format string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: parseLevel(level)}
	var h slog.Handler
	if strings.EqualFold(format, "text") {
		h = slog.NewTextHandler(os.Stdout, opts)
	} else {
		h = slog.NewJSONHandler(os.Stdout, opts)
	}
	return slog.New(h)
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
