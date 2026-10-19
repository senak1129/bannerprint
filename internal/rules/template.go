package rules

import (
	"strings"
	"text/template"
)

// funcs 是规则模板可用的**全部**函数。
//
// 刻意限制为 4 个无副作用的纯函数：规则文件是「数据」，不允许承载任意逻辑
// （否则规则文件就变成了代码，解耦失去意义，同时带来注入风险）。
var funcs = template.FuncMap{
	"osFrom":  osFrom,
	"trimV":   trimV,
	"default": defaultStr,
	"lower":   strings.ToLower,
}

// osTable 是「发行版线索 → 规范名」映射。
//
// 顺序敏感：opensuse 必须排在 suse 之前，否则 "openSUSE" 会被误判为 "SUSE"。
// 只做**显式**线索识别，不从产品名反推操作系统（如 IIS 不自动填 Windows）。
var osTable = []struct {
	needle    string
	canonical string
}{
	{"opensuse", "openSUSE"},
	{"ubuntu", "Ubuntu"},
	{"debian", "Debian"},
	{"centos", "CentOS"},
	{"red hat", "Red Hat"},
	{"rhel", "Red Hat"},
	{"almalinux", "AlmaLinux"},
	{"rocky", "Rocky"},
	{"alpine", "Alpine"},
	{"amazon linux", "Amazon Linux"},
	{"oracle linux", "Oracle Linux"},
	{"freebsd", "FreeBSD"},
	{"openbsd", "OpenBSD"},
	{"netbsd", "NetBSD"},
	{"windows", "Windows"},
	{"fedora", "Fedora"},
	{"gentoo", "Gentoo"},
	{"arch linux", "Arch"},
	{"suse", "SUSE"},
}

// osFrom 从注释串中提取发行版规范名，例如：
//
//	"Ubuntu-3"                → "Ubuntu"
//	"Debian-1"                → "Debian"
//	"Ubuntu"                  → "Ubuntu"
//	""                        → ""
func osFrom(s string) string {
	if s == "" {
		return ""
	}
	lower := strings.ToLower(s)
	for _, e := range osTable {
		if strings.Contains(lower, e.needle) {
			return e.canonical
		}
	}
	return ""
}

// trimV 去掉版本号前缀 v/V（"v1.24.0" → "1.24.0"），保留 p1、rc1 等后缀。
func trimV(s string) string {
	return strings.TrimPrefix(strings.TrimPrefix(s, "v"), "V")
}

// defaultStr 在 s 为空时返回 def，用于规则里给可选字段兜底。
func defaultStr(def, s string) string {
	if s == "" {
		return def
	}
	return s
}

// parseTpl 解析字段模板。
//
// missingkey=zero 让「捕获组不存在」表现为空串而非 "<no value>"，
// 避免把渲染噪声写进 product/version 字段。
func parseTpl(s string) (*template.Template, error) {
	return template.New("field").Option("missingkey=zero").Funcs(funcs).Parse(s)
}

// renderTpl 执行模板；nil 模板视为空串（该规则未配置此字段）。
func renderTpl(t *template.Template, data map[string]string) (string, error) {
	if t == nil {
		return "", nil
	}
	var sb strings.Builder
	if err := t.Execute(&sb, data); err != nil {
		return "", err
	}
	return strings.TrimSpace(sb.String()), nil
}
