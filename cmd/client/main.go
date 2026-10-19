// Command client 是一个独立的一次性程序：读本地 JSON → 调 server → 展示识别结果。
//
// 用法：
//
//	client -file /data/input.json                      # 表格输出到 stdout
//	client -file /data/input.json -format json         # JSON 输出，可管道给 jq
//	client -file /data/input.json -out /tmp/result.json
//
// 退出码（脚本据此判断失败原因，见 spec §8.4）：
//
//	0 成功 · 2 参数/输入错误 · 3 连不上 server · 4 服务端错误 · 5 写盘失败
//
// 日志一律走 stderr，结果走 stdout —— 这是 Unix 惯例，也是 `> result.json` 能直接用的前提。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bannerprint/bannerprint/internal/client"
	"github.com/bannerprint/bannerprint/internal/jsonx"
	"github.com/bannerprint/bannerprint/internal/model"
)

// version 由构建时注入，与 server 共用同一套 ldflags。
var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		file    = fs.String("file", "", "input JSON file (array or NDJSON) [required]")
		server  = fs.String("server", envOr("SERVER_URL", "http://127.0.0.1:8080"), "server base URL")
		format  = fs.String("format", "table", "output format: table|json")
		out     = fs.String("out", "", "write result to file instead of stdout")
		batch   = fs.Int("batch", 500, "items per request")
		timeout = fs.Duration("timeout", 30*time.Second, "per-request timeout")
		wait    = fs.Duration("wait", 30*time.Second, "max time to wait for server readiness")
		showVer = fs.Bool("version", false, "print version and exit")
	)

	if err := fs.Parse(os.Args[1:]); err != nil {
		return client.ExitUsage
	}
	if *showVer {
		fmt.Println(version)
		return client.ExitOK
	}
	if *file == "" {
		fmt.Fprintln(os.Stderr, "error: -file is required")
		fs.Usage()
		return client.ExitUsage
	}
	if *format != "table" && *format != "json" {
		fmt.Fprintf(os.Stderr, "error: unknown -format %q (want table|json)\n", *format)
		return client.ExitUsage
	}

	items, err := loadItems(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return client.ExitUsage
	}
	fmt.Fprintf(os.Stderr, "client %s: loaded %d items from %s, server=%s\n",
		version, len(items), *file, *server)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	opt := client.DefaultOptions()
	opt.ServerURL = *server
	opt.BatchSize = *batch
	opt.Timeout = *timeout
	opt.HealthWait = *wait

	start := time.Now()
	results, err := client.Run(ctx, items, opt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return client.ExitCode(err)
	}
	fmt.Fprintf(os.Stderr, "client %s: %d results in %s\n",
		version, len(results), time.Since(start).Round(time.Millisecond))

	if err := write(*out, *format, results); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return client.ExitOutputError
	}
	return client.ExitOK
}

// loadItems 与 server 共用同一套宽松解码器：
// 客户端能读进来的数据，服务端必然也能解析，不会出现「本地能跑、服务端 400」的割裂。
func loadItems(path string) ([]model.Item, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	items, err := jsonx.UnmarshalItems(data)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return items, nil
}

// write 把结果写到文件或 stdout。
func write(path, format string, results []model.Result) error {
	var w *os.File
	if path == "" {
		w = os.Stdout
	} else {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		defer f.Close()
		w = f
	}

	if format == "json" {
		return client.RenderJSON(w, results)
	}
	return client.RenderTable(w, results)
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}
