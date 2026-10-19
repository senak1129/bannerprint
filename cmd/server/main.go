// Command server 是 banner 指纹识别服务端。
//
// 运维约定（对应 spec §4.3 / §10.4）：
//   - 启动前加载并校验全部规则，失败即退出（fail fast），绝不带着半套规则服务；
//   - 内置 `healthcheck` 子命令供容器探针使用 —— distroless 镜像里没有 curl/wget，
//     探针只能由二进制自己完成；
//   - 收到 SIGTERM 后先停止接收新连接，再给在途请求排水，最后退出。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bannerprint/bannerprint/internal/api"
	"github.com/bannerprint/bannerprint/internal/config"
	"github.com/bannerprint/bannerprint/internal/engine"
	"github.com/bannerprint/bannerprint/internal/obs"
	"github.com/bannerprint/bannerprint/internal/rules"
)

// version 由构建时注入：
//
//	go build -ldflags "-s -w -X main.version=$VERSION"
//
// 未注入时保持 "dev"，/health 会如实反映。
var version = "dev"

func main() {
	// 探针子命令必须在任何初始化之前拦截：
	// 它被高频调用，不能去加载规则、更不能占用 8080 端口。
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck(os.Args[2:]))
	}
	if len(os.Args) > 1 && (os.Args[1] == "-version" || os.Args[1] == "--version") {
		fmt.Println(version)
		return
	}
	os.Exit(run())
}

func run() int {
	cfg := config.Load()
	log := obs.New(cfg.LogLevel, cfg.LogFormat)

	// 规则加载失败 = 能力缺失，必须拒绝启动。
	// 否则服务会「健康地」返回一堆 unknown，比直接失败更难排查。
	ruleset, err := rules.Load(cfg.RulesDir)
	if err != nil {
		log.Error("load rules failed", "error", err)
		return 1
	}

	eng := engine.New(ruleset, cfg.MaxBannerBytes, cfg.EnableTLSDetect)
	srv := api.New(cfg, eng, ruleset.Stats, log, version)

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Info("server starting",
		"version", version,
		"addr", cfg.Addr,
		"rules_dir", cfg.RulesDir,
		"rules_loaded", ruleset.Stats.Rules,
		"rules_files", ruleset.Stats.Files,
		"rules_source", ruleset.Stats.Source,
		"max_batch_items", cfg.MaxBatchItems,
		"tls_detect", cfg.EnableTLSDetect,
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 缓冲 1：保证 goroutine 不会因为无人接收而泄漏。
	errCh := make(chan error, 1)
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received")
	case err := <-errCh:
		log.Error("server error", "error", err)
		return 1
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Error("graceful shutdown failed", "error", err)
		return 1
	}
	log.Info("server stopped")
	return 0
}

// healthcheck 查询 /health 并以退出码表达结果：
//
//	0 = 就绪（HTTP 200 且 engine_ready=true）
//	1 = 未就绪 / 不可达 / 响应异常
//	2 = 参数错误
//
// 刻意校验 engine_ready，而不是「能连上就算健康」——容器已启动但规则未加载
// 的中间态不应被编排层当成可用实例。
func healthcheck(args []string) int {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	url := fs.String("url", "http://127.0.0.1:8080/health", "health endpoint URL")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(*url)
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}

	var payload struct {
		Status string `json:"status"`
		Checks struct {
			EngineReady bool `json:"engine_ready"`
		} `json:"checks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return 1
	}
	if !payload.Checks.EngineReady {
		return 1
	}
	if payload.Status != "ok" && payload.Status != "degraded" {
		return 1
	}
	return 0
}
