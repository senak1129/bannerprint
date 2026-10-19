package api_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bannerprint/bannerprint/internal/api"
	"github.com/bannerprint/bannerprint/internal/config"
	"github.com/bannerprint/bannerprint/internal/engine"
	"github.com/bannerprint/bannerprint/internal/model"
	"github.com/bannerprint/bannerprint/internal/rules"
)

func newHandler(t *testing.T, mutate func(*config.Config)) http.Handler {
	t.Helper()
	cfg := config.Default()
	cfg.RulesDir = "../../rules"
	if mutate != nil {
		mutate(&cfg)
	}
	set, err := rules.Load(cfg.RulesDir)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := api.New(cfg, engine.New(set, cfg.MaxBannerBytes, cfg.EnableTLSDetect), set.Stats, log, "test")
	return srv.Handler()
}

func do(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestFingerprintHappyPath 验证最小可用链路：一条 SSH 输入 → 一条结果。
func TestFingerprintHappyPath(t *testing.T) {
	h := newHandler(t, nil)
	rec := do(h, http.MethodPost, "/fingerprint",
		`[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}]`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got []model.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Protocol != "SSH" || got[0].Product != "OpenSSH" || got[0].Version != "8.9p1" || got[0].OSHint != "Ubuntu" {
		t.Errorf("unexpected result: %+v", got[0])
	}
}

// TestUnknownIsNotAnError 是本服务的核心契约：认不出来 → 200 + unknown。
func TestUnknownIsNotAnError(t *testing.T) {
	h := newHandler(t, nil)
	rec := do(h, http.MethodPost, "/fingerprint",
		`[{"ip":"1.2.3.23","port":12345,"banner":"QUIT\r\n"}]`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got []model.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].Protocol != model.ProtocolUnknown || got[0].Confidence != 0 {
		t.Errorf("unexpected result: %+v", got)
	}
}

// TestBatchPreservesOrderAndArity 验证 1:1 与保序：这是客户端按序展示的前提。
func TestBatchPreservesOrderAndArity(t *testing.T) {
	h := newHandler(t, nil)
	rec := do(h, http.MethodPost, "/fingerprint", `[
		{"ip":"a","port":1,"banner":"SSH-2.0-OpenSSH_9.3 Debian-1"},
		{"ip":"b","port":2,"banner":"garbage"},
		{"ip":"c","port":3,"banner":"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41"}
	]`)
	var got []model.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	if got[0].IP != "a" || got[1].IP != "b" || got[2].IP != "c" {
		t.Errorf("order broken: %+v", got)
	}
	if got[1].Protocol != model.ProtocolUnknown {
		t.Errorf("middle item should be unknown, got %+v", got[1])
	}
}

// TestErrorTaxonomy 覆盖 4xx 分支：错误必须是结构化 JSON，而不是纯文本。
func TestErrorTaxonomy(t *testing.T) {
	h := newHandler(t, nil)

	cases := []struct {
		name   string
		method string
		path   string
		body   string
		status int
		code   string
	}{
		{"malformed json", http.MethodPost, "/fingerprint", `{"ip":`, http.StatusBadRequest, "invalid_json"},
		{"empty batch", http.MethodPost, "/fingerprint", `[]`, http.StatusBadRequest, "empty_batch"},
		{"wrong method", http.MethodGet, "/fingerprint", "", http.StatusMethodNotAllowed, "method_not_allowed"},
		{"unknown route", http.MethodGet, "/nope", "", http.StatusNotFound, "not_found"},
		{"health wrong method", http.MethodPost, "/health", "", http.StatusMethodNotAllowed, "method_not_allowed"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(h, tc.method, tc.path, tc.body)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tc.status, rec.Body.String())
			}
			var payload struct {
				Error struct {
					Code      string `json:"code"`
					RequestID string `json:"request_id"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
				t.Fatalf("error body is not JSON: %v (%s)", err, rec.Body.String())
			}
			if payload.Error.Code != tc.code {
				t.Errorf("code = %q, want %q", payload.Error.Code, tc.code)
			}
			if payload.Error.RequestID == "" {
				t.Error("request_id must not be empty")
			}
		})
	}
}

// TestPayloadTooLarge 验证体积上限走 413，而不是把内存撑爆或返回 500。
func TestPayloadTooLarge(t *testing.T) {
	h := newHandler(t, func(c *config.Config) { c.MaxBodyBytes = 32 })
	rec := do(h, http.MethodPost, "/fingerprint",
		`[{"ip":"1.2.3.4","port":22,"banner":"`+strings.Repeat("A", 200)+`"}]`)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestHealthReportsEngineReady 验证健康检查反映真实就绪状态，而非固定 200。
func TestHealthReportsEngineReady(t *testing.T) {
	h := newHandler(t, nil)
	rec := do(h, http.MethodGet, "/health", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var payload struct {
		Status string `json:"status"`
		Rules  struct {
			Loaded int `json:"loaded"`
			Files  int `json:"files"`
		} `json:"rules"`
		Checks struct {
			RulesLoaded bool `json:"rules_loaded"`
			EngineReady bool `json:"engine_ready"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Status != "ok" || !payload.Checks.EngineReady || !payload.Checks.RulesLoaded {
		t.Errorf("unexpected health payload: %+v", payload)
	}
	if payload.Rules.Loaded == 0 || payload.Rules.Files == 0 {
		t.Errorf("rules stats missing: %+v", payload.Rules)
	}
}

// TestRequestIDEchoed 验证请求 ID 回写，便于用户侧与日志对齐。
func TestRequestIDEchoed(t *testing.T) {
	h := newHandler(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("X-Request-ID", "trace-123")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("X-Request-ID"); got != "trace-123" {
		t.Errorf("X-Request-ID = %q, want trace-123", got)
	}
}

// TestAuthTokenOptional 验证 API_TOKEN 的开关语义：默认不鉴权，配置后必须带 token。
func TestAuthTokenOptional(t *testing.T) {
	open := newHandler(t, nil)
	if rec := do(open, http.MethodGet, "/health", ""); rec.Code != http.StatusOK {
		t.Fatalf("without token: status = %d, want 200", rec.Code)
	}

	locked := newHandler(t, func(c *config.Config) { c.APIToken = "s3cret" })
	if rec := do(locked, http.MethodGet, "/health", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("without bearer: status = %d, want 401", rec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	rec := httptest.NewRecorder()
	locked.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("with bearer: status = %d, want 200", rec.Code)
	}
}
