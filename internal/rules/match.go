package rules

import (
	"sort"
	"unicode/utf8"

	"github.com/bannerprint/bannerprint/internal/model"
)

// Match 对一条 banner 应用指定协议的全部规则，返回候选列表（可能为空）。
//
// 输入：
//   - raw    ：原始 banner 字节
//   - fields ：该协议 Parser 抽出的语法字段，键形如 "http.server"
//
// 匹配过程：
//  1. 按规则声明的来源取待匹配文本（raw 或某个字段）；
//  2. 正则命中后，把命名捕获组与 Parser 字段合并成模板数据；
//     —— 捕获组用短名（product/version/os），Parser 字段用带点的全名
//     （ssh.comment），因此 `{{ .version }}` 与 `{{ index . "ssh.comment" }}`
//     不会互相遮挡；
//  3. 渲染 product/version/os_hint 模板；
//  4. 计算置信度：基准分 + if_empty 覆盖（例如版本捕获为空时降到 0.85）。
//
// 返回的候选未排序，由 engine 统一仲裁。
func (s *Set) Match(protocol string, raw []byte, fields map[string]string) []model.Candidate {
	rs := s.byProtocol[protocol]
	if len(rs) == 0 {
		return nil
	}

	// 非 UTF-8 数据（MySQL 握手包、TLS record）按 latin-1 逐字节映射，
	// 保证 ASCII 锚点仍可被正则命中，且不会因非法编码整条丢弃。
	text := ""
	if utf8.Valid(raw) {
		text = string(raw)
	} else {
		text = latin1(raw)
	}

	out := make([]model.Candidate, 0, len(rs))
	for i := range rs {
		r := &rs[i]

		var input string
		if r.Source == "raw" {
			input = text
		} else {
			v, ok := fields[r.Field]
			if !ok || v == "" {
				continue
			}
			input = v
		}

		m := r.re.FindStringSubmatch(input)
		if m == nil {
			continue
		}

		data := make(map[string]string, len(m)+len(fields))
		for j, name := range r.re.SubexpNames() {
			if j == 0 || name == "" {
				continue
			}
			data[name] = m[j]
		}
		for k, v := range fields {
			data[k] = v
		}

		product, err := renderTpl(r.tplProduct, data)
		if err != nil {
			continue // 单条规则模板执行失败不应影响其他规则
		}
		version, err := renderTpl(r.tplVersion, data)
		if err != nil {
			continue
		}
		osHint, err := renderTpl(r.tplOS, data)
		if err != nil {
			continue
		}

		conf := r.base
		if len(r.ifEmpty) > 0 {
			// 排序保证多条 if_empty 时结果确定（YAML map 无序）
			keys := make([]string, 0, len(r.ifEmpty))
			for k := range r.ifEmpty {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if data[k] == "" {
					conf = r.ifEmpty[k]
				}
			}
		}

		out = append(out, model.Candidate{
			Protocol:   r.Protocol,
			Product:    product,
			Version:    version,
			OSHint:     osHint,
			Confidence: conf,
			Priority:   r.Priority,
			RuleID:     r.ID,
		})
	}
	return out
}

// latin1 把字节串逐字节映射为 rune，再编码为 UTF-8 字符串。
// 这不是「字符集转换」，只是为了让正则引擎能处理任意字节输入。
func latin1(b []byte) string {
	buf := make([]rune, len(b))
	for i, c := range b {
		buf[i] = rune(c)
	}
	return string(buf)
}
