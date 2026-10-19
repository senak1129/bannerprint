package api

import (
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/bannerprint/bannerprint/internal/jsonx"
	"github.com/bannerprint/bannerprint/internal/model"
)

// handleFingerprint 处理批量识别。
//
// 错误分层（对应 spec §4.2）：
//   - 请求**本身**不合法（非 JSON、空数组、超限）→ 4xx；
//   - 请求合法但**某条数据**认不出来 → 200 + unknown。
//
// 这条边界是本服务最重要的契约：客户端的批量任务不应因为个别脏数据整体失败。
func (s *Server) handleFingerprint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "use POST /fingerprint")
		return
	}

	// MaxBytesReader 在超限时同时阻断后续读取，避免内存被撑爆。
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, r, http.StatusRequestEntityTooLarge, "payload_too_large", "request body exceeds MAX_BODY_BYTES")
			return
		}
		writeError(w, r, http.StatusBadRequest, "invalid_body", "failed to read request body")
		return
	}

	items, err := jsonx.UnmarshalItems(body)
	if err != nil {
		if errors.Is(err, jsonx.ErrEmpty) {
			writeError(w, r, http.StatusBadRequest, "empty_batch", "request must contain at least one item")
			return
		}
		writeError(w, r, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	if len(items) > s.cfg.MaxBatchItems {
		writeError(w, r, http.StatusRequestEntityTooLarge, "payload_too_large", "batch size exceeds MAX_BATCH_ITEMS")
		return
	}

	results := s.eng.FingerprintBatch(items, s.cfg.Workers)

	// 供访问日志统计（不记录 banner 内容，只记录数量）。
	if info, ok := r.Context().Value(ctxKeyInfo).(*requestInfo); ok {
		info.Items = len(results)
		for _, res := range results {
			if res.Protocol == model.ProtocolUnknown {
				info.Unknown++
			}
		}
	}

	writeJSON(w, http.StatusOK, results)
}

// healthResponse 是 /health 的响应结构（字段顺序即 JSON 顺序）。
type healthResponse struct {
	Status  string      `json:"status"`
	Version string      `json:"version"`
	UptimeS int64       `json:"uptime_s"`
	Rules   healthRules `json:"rules"`
	Checks  healthChecks `json:"checks"`
}

type healthRules struct {
	Loaded   int    `json:"loaded"`
	Files    int    `json:"files"`
	Errors   int    `json:"errors"`
	LoadedAt string `json:"loaded_at"`
}

type healthChecks struct {
	RulesLoaded bool `json:"rules_loaded"`
	EngineReady bool `json:"engine_ready"`
}

// handleHealth 是编排层真正可用的健康探针：
//
//   - 200 表示「规则已加载、引擎可服务」；
//   - 503 表示「未就绪」。
//
// docker-compose 的 healthcheck 与 client 的启动等待都依赖它，
// 因此它必须是纯内存读取（< 5ms），不能在这里做任何 I/O。
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "use GET /health")
		return
	}

	ready := s.ready.Load() && s.rules.Rules > 0
	status := "ok"
	code := http.StatusOK
	if !ready {
		status = "not_ready"
		code = http.StatusServiceUnavailable
	}

	resp := healthResponse{
		Status:  status,
		Version: s.version,
		UptimeS: int64(time.Since(s.start).Seconds()),
		Rules: healthRules{
			Loaded:   s.rules.Rules,
			Files:    s.rules.Files,
			Errors:   s.rules.Errors,
			LoadedAt: s.rules.LoadedAt.UTC().Format(time.RFC3339),
		},
		Checks: healthChecks{
			RulesLoaded: s.rules.Rules > 0,
			EngineReady: ready,
		},
	}
	writeJSON(w, code, resp)
}
