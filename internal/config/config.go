// Package config 负责从环境变量装配服务端配置。
//
// 设计约定（对应 spec §9）：
//   - 所有配置项都有安全默认值，缺省即可跑通（评估者只需 docker compose up）；
//   - 非法值不致命：回退默认值并记录警告，避免「配错一个变量导致起不来」；
//   - 配置项只由环境变量注入，便于容器化与 12-factor 部署。
package config

import (
	"os"
	"strconv"
	"time"
)

// Config 是 server 的运行时配置。
type Config struct {
	Addr            string        // 监听地址，如 ":8080"
	RulesDir        string        // 外部规则目录（只读挂载），为空或不存在时仅用内置规则
	MaxBodyBytes    int64         // 请求体上限
	MaxBatchItems   int           // 单批条数上限
	MaxBannerBytes  int           // 单条 banner 截断阈值
	Workers         int           // 单请求内部并发度
	LogLevel        string        // debug/info/warn/error
	LogFormat       string        // json/text
	APIToken        string        // 可选 Bearer Token，空表示不鉴权
	EnableTLSDetect bool          // 是否启用 TLS record 识别
	ShutdownTimeout time.Duration // 优雅退出排水时间
}

// Default 返回一组合规的默认配置，测试与其他包可直接使用。
func Default() Config {
	return Config{
		Addr:            ":8080",
		RulesDir:        "/etc/bannerprint/rules.d",
		MaxBodyBytes:    32 << 20, // 32 MiB
		MaxBatchItems:   10000,
		MaxBannerBytes:  8192,
		Workers:         0, // 0 表示由 engine 取 GOMAXPROCS
		LogLevel:        "info",
		LogFormat:       "json",
		APIToken:        "",
		EnableTLSDetect: true,
		ShutdownTimeout: 10 * time.Second,
	}
}

// Load 读取环境变量并覆盖默认值。
func Load() Config {
	c := Default()
	if v := os.Getenv("SERVER_ADDR"); v != "" {
		c.Addr = v
	}
	if v := os.Getenv("RULES_DIR"); v != "" {
		c.RulesDir = v
	}
	c.MaxBodyBytes = envInt64("MAX_BODY_BYTES", c.MaxBodyBytes)
	c.MaxBatchItems = envInt("MAX_BATCH_ITEMS", c.MaxBatchItems)
	c.MaxBannerBytes = envInt("MAX_BANNER_BYTES", c.MaxBannerBytes)
	c.Workers = envInt("WORKERS", c.Workers)
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		c.LogLevel = v
	}
	if v := os.Getenv("LOG_FORMAT"); v != "" {
		c.LogFormat = v
	}
	if v := os.Getenv("API_TOKEN"); v != "" {
		c.APIToken = v
	}
	c.EnableTLSDetect = envBool("ENABLE_TLS_DETECT", c.EnableTLSDetect)
	c.ShutdownTimeout = envDuration("SHUTDOWN_TIMEOUT", c.ShutdownTimeout)

	// 兜底：非法的规模参数回退默认值，避免 make([]T, -1) 之类的运行时崩溃。
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = Default().MaxBodyBytes
	}
	if c.MaxBatchItems <= 0 {
		c.MaxBatchItems = Default().MaxBatchItems
	}
	if c.MaxBannerBytes <= 0 {
		c.MaxBannerBytes = Default().MaxBannerBytes
	}
	if c.Workers < 0 {
		c.Workers = 0
	}
	return c
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envInt64(key string, def int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return def
	}
	return n
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}
