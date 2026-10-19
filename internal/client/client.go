// Package client 实现 bannerprint 的客户端逻辑：读取本地扫描数据 → 调用 server → 渲染结果。
//
// 设计约束（对应 spec §8）：
//   - 客户端是**独立程序**，不 import server 的识别逻辑，只依赖 HTTP 契约与 model；
//   - 启动前轮询 /health：`docker compose run` 不会等待 depends_on 的健康条件，
//     这一层自旋是「启动依赖真实生效」的第二道保险；
//   - 分片串行发送：单请求过大容易被网关/服务端限额拒绝，串行则避免压垮单实例；
//   - 4xx 立即失败（请求本身有问题，重试无意义），5xx/网络错误才指数退避重试。
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bannerprint/bannerprint/internal/model"
)

// 退出码（与 spec §8.4 一致，便于脚本判断失败原因）。
const (
	ExitOK          = 0
	ExitUsage       = 2 // 参数/输入文件错误
	ExitUnreachable = 3 // 连不上 server / 健康检查超时
	ExitServerError = 4 // server 返回非 2xx 或响应无法解析
	ExitOutputError = 5 // 结果写盘失败
)

// Error 携带退出码，让 main 只需一次映射即可把错误翻译成进程状态。
type Error struct {
	Code int
	Err  error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// Errorf 构造带退出码的错误。
func Errorf(code int, format string, args ...any) *Error {
	return &Error{Code: code, Err: fmt.Errorf(format, args...)}
}

// Options 是客户端运行参数。
type Options struct {
	ServerURL   string        // 形如 http://server:8080
	BatchSize   int           // 单次 POST 的条数
	Timeout     time.Duration // 单次请求超时
	HealthWait  time.Duration // 启动时等待 server 就绪的上限
	MaxAttempts int           // 单批最多尝试次数（含首次）
}

// DefaultOptions 返回可直接使用的默认值（环境变量由 cmd 层覆盖）。
func DefaultOptions() Options {
	return Options{
		ServerURL:   "http://127.0.0.1:8080",
		BatchSize:   500,
		Timeout:     30 * time.Second,
		HealthWait:  30 * time.Second,
		MaxAttempts: 3,
	}
}

// Run 完成「等待就绪 → 分片识别 → 汇总」全流程。
// 返回的 results 与入参 items 严格 1:1 且保持原顺序。
func Run(ctx context.Context, items []model.Item, opt Options) ([]model.Result, error) {
	if opt.BatchSize <= 0 {
		opt.BatchSize = DefaultOptions().BatchSize
	}
	if opt.MaxAttempts <= 0 {
		opt.MaxAttempts = DefaultOptions().MaxAttempts
	}

	hc := &http.Client{Timeout: opt.Timeout}
	if err := WaitHealthy(ctx, hc, opt.ServerURL, opt.HealthWait); err != nil {
		return nil, err
	}

	results := make([]model.Result, 0, len(items))
	for start := 0; start < len(items); start += opt.BatchSize {
		end := start + opt.BatchSize
		if end > len(items) {
			end = len(items)
		}
		part, err := fingerprintBatch(ctx, hc, opt, items[start:end])
		if err != nil {
			return nil, err
		}
		results = append(results, part...)
	}
	return results, nil
}

// WaitHealthy 轮询 /health 直到 200 且 checks.engine_ready=true。
//
// 每 1s 一次，直到 wait 耗尽。这样在 `docker compose run`（不等待依赖）
// 和本机先起 client 后起 server 两种情况下都能自然衔接。
func WaitHealthy(ctx context.Context, hc *http.Client, baseURL string, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	url := strings.TrimRight(baseURL, "/") + "/health"

	var lastErr error
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return Errorf(ExitUsage, "invalid server url %q: %v", baseURL, err)
		}
		resp, err := hc.Do(req)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var h struct {
					Checks struct {
						EngineReady bool `json:"engine_ready"`
					} `json:"checks"`
				}
				if json.Unmarshal(body, &h) == nil && h.Checks.EngineReady {
					return nil
				}
				lastErr = fmt.Errorf("server not ready: %s", strings.TrimSpace(string(body)))
			} else {
				lastErr = fmt.Errorf("health returned %d", resp.StatusCode)
			}
		} else {
			lastErr = err
		}

		if time.Now().Add(time.Second).After(deadline) {
			return Errorf(ExitUnreachable, "server %s not ready within %s: %v", baseURL, wait, lastErr)
		}
		select {
		case <-ctx.Done():
			return Errorf(ExitUnreachable, "cancelled while waiting for server: %v", ctx.Err())
		case <-time.After(time.Second):
		}
	}
}

// fingerprintBatch 发送单批数据，带指数退避重试。
func fingerprintBatch(ctx context.Context, hc *http.Client, opt Options, items []model.Item) ([]model.Result, error) {
	// Item.Banner 是 []byte，标准库会按 base64 编码 —— 与 server 的宽松解码器不兼容。
	// 因此这里显式构造 {ip,port,banner:string} 的传输形态。
	type wireItem struct {
		IP     string `json:"ip"`
		Port   int    `json:"port"`
		Banner string `json:"banner"`
	}
	wire := make([]wireItem, len(items))
	for i, it := range items {
		wire[i] = wireItem{IP: it.IP, Port: it.Port, Banner: string(it.Banner)}
	}
	payload, err := json.Marshal(wire)
	if err != nil {
		return nil, Errorf(ExitUsage, "encode batch: %v", err)
	}

	url := strings.TrimRight(opt.ServerURL, "/") + "/fingerprint"
	backoff := 500 * time.Millisecond

	var lastErr error
	for attempt := 1; attempt <= opt.MaxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
		if err != nil {
			return nil, Errorf(ExitUsage, "build request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := hc.Do(req)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
			resp.Body.Close()
			switch {
			case readErr != nil:
				lastErr = readErr
			case resp.StatusCode == http.StatusOK:
				var results []model.Result
				if err := json.Unmarshal(body, &results); err != nil {
					return nil, Errorf(ExitServerError, "decode response: %v", err)
				}
				if len(results) != len(items) {
					return nil, Errorf(ExitServerError,
						"result count mismatch: sent %d, got %d", len(items), len(results))
				}
				return results, nil
			case resp.StatusCode >= 400 && resp.StatusCode < 500:
				// 4xx 是请求本身的问题（非法 JSON、超限），重试不会变好。
				return nil, Errorf(ExitServerError, "server rejected batch: %d %s", resp.StatusCode, snippet(body))
			default:
				lastErr = fmt.Errorf("status %d: %s", resp.StatusCode, snippet(body))
			}
		} else {
			lastErr = err
		}

		if attempt < opt.MaxAttempts {
			select {
			case <-ctx.Done():
				return nil, Errorf(ExitServerError, "cancelled: %v", ctx.Err())
			case <-time.After(backoff):
			}
			backoff *= 2
		}
	}
	return nil, Errorf(ExitServerError, "batch failed after %d attempts: %v", opt.MaxAttempts, lastErr)
}

// snippet 截断错误响应，避免日志被大段 HTML/JSON 淹没。
func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

// IsError 判断 err 是否由本包产生，并取出退出码。
func exitCode(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ExitServerError
}

// ExitCode 把任意错误映射为进程退出码，供 cmd 层使用。
func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	return exitCode(err)
}
