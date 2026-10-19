// Package rules 负责加载、校验并执行「产品指纹规则」。
//
// 这是「识别规则与程序代码解耦」（spec §3 / §7.2）的落点：
//
//	Parser（internal/parsers）= 协议**语法**：SSH 标识串长什么样、MySQL 握手包
//	  第 5 个字节是 0x0A —— 这类知识稳定、少量，属于代码。
//	Rule（本包 + rules/*.yaml）= 产品**知识**：nginx 的版本号怎么截、Apache 的
//	  规范写法是什么、哪个发行版字符串映射成 Ubuntu —— 这类知识会不断新增，
//	  属于数据。
//
// 因此本文件不允许出现任何具体产品名；产品名只存在于 rules/*.yaml。
// 新增一个产品应做到「只改 YAML，不改一行 Go 代码」。
package rules

import (
	"regexp"
	"text/template"
	"time"
)

// 允许的协议枚举（与 spec §5 一致）。未知一律走 unknown，不在此枚举内。
var allowedProtocols = map[string]bool{
	"SSH":   true,
	"HTTP":  true,
	"MySQL": true,
	"Redis": true,
	"FTP":   true,
	"TLS":   true,
}

// Stats 是规则加载的统计信息，直接用于 /health 与启动日志。
type Stats struct {
	Files    int       // 参与加载的规则文件数
	Rules    int       // 编译成功的规则条数
	Errors   int       // 加载失败的条数（fail fast 时为 0）
	LoadedAt time.Time // 加载完成时间（UTC）
	Source   string    // embedded / embedded+dir
}

// Rule 是编译后的单条规则。
type Rule struct {
	ID       string // 全局唯一，如 http.nginx
	Protocol string // 所属协议
	Priority int    // 同分仲裁用，0–1000

	// 匹配来源：
	//   source=raw   → 直接匹配原始 banner（按 latin-1 映射为字符串）
	//   source=field → 匹配 Parser 产出的字段，如 http.server
	Source string
	Field  string
	re     *regexp.Regexp

	// 以下三个模板在加载期就已 Parse，匹配期只做 Execute，
	// 避免每条数据重复解析模板（性能与错误处理都更可控）。
	tplProduct *template.Template
	tplVersion *template.Template
	tplOS      *template.Template

	base    float64            // 基准置信度
	ifEmpty map[string]float64 // 指定捕获组为空时的置信度覆盖，如 version→0.85
	file    string             // 来源文件名，用于排序与排障
}

// Set 是一个不可变的规则集合。加载完成后只读，可安全并发使用。
type Set struct {
	byProtocol map[string][]Rule
	Stats      Stats
}

// RuleIDs 返回所有规则 ID（按加载顺序），供测试与 /health 调试使用。
func (s *Set) RuleIDs() []string {
	out := make([]string, 0, s.Stats.Rules)
	for _, proto := range []string{"SSH", "HTTP", "MySQL", "Redis", "FTP", "TLS"} {
		for _, r := range s.byProtocol[proto] {
			out = append(out, r.ID)
		}
	}
	return out
}

// Count 返回规则总数。
func (s *Set) Count() int { return s.Stats.Rules }

// ProtocolCount 返回指定协议的规则数，便于自检「某个协议是否根本没加载」。
func (s *Set) ProtocolCount(protocol string) int { return len(s.byProtocol[protocol]) }

// ---- YAML 反序列化用的原始结构体 ----
// 与规则文件一一对应；字段名刻意保持简短，使 YAML 可读性优先。

type rawFile struct {
	Version  int       `yaml:"version"`
	Protocol string    `yaml:"protocol"`
	Rules    []rawRule `yaml:"rules"`
}

type rawRule struct {
	ID         string            `yaml:"id"`
	Priority   int               `yaml:"priority"`
	Match      rawMatch          `yaml:"match"`
	Fields     map[string]string `yaml:"fields"`
	Confidence rawConfidence     `yaml:"confidence"`
}

type rawMatch struct {
	Source string `yaml:"source"`
	Field  string `yaml:"field"`
	Regex  string `yaml:"regex"`
}

type rawConfidence struct {
	Base    float64            `yaml:"base"`
	IfEmpty map[string]float64 `yaml:"if_empty"`
}
