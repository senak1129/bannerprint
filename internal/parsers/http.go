package parsers

import (
	"regexp"
	"strings"
)

// httpStatusRe 匹配状态行，用于判定「这是不是一个 HTTP 响应」。
// 大小写不敏感：个别设备会返回小写 http/1.1。
var httpStatusRe = regexp.MustCompile(`(?i)^HTTP/\d(?:\.\d)?\s+\d{3}`)

type httpParser struct{}

func (httpParser) Name() string     { return "http" }
func (httpParser) Protocol() string { return "HTTP" }
func (httpParser) Priority() int    { return 100 }

// Parse 抽取状态行与关键响应头。
//
// 只取第一个 Server 头：多级代理会在响应里追加自己的 Server，
// 首个通常最接近真实后端；这也保证了「同输入同输出」的确定性。
// X-Powered-By 仅作为辅助字段保留，不参与产品判定。
func (httpParser) Parse(banner []byte) (map[string]string, bool) {
	lines := strings.Split(string(banner), "\n")

	var (
		statusLine string
		server     string
		poweredBy  string
	)
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		trimmed := strings.TrimSpace(line)

		// 状态行可能前面有噪声行，因此每行都尝试匹配，只取第一处。
		if statusLine == "" && httpStatusRe.MatchString(trimmed) {
			statusLine = trimmed
			continue
		}

		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(line[:idx]))
		value := strings.TrimSpace(line[idx+1:])
		switch name {
		case "server":
			if server == "" {
				server = value
			}
		case "x-powered-by":
			if poweredBy == "" {
				poweredBy = value
			}
		}
	}

	if statusLine == "" {
		return nil, false
	}

	fields := map[string]string{"http.status_line": statusLine}
	if server != "" {
		fields["http.server"] = server
	}
	if poweredBy != "" {
		fields["http.powered_by"] = poweredBy
	}
	return fields, true
}
