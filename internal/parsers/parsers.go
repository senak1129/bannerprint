// Package parsers 实现「协议语法」解析器。
//
// 职责边界（对应 spec §3 / §7.1）：
//
//	Parser 只回答两个问题：这条 banner **像不像**某个协议？能从中抽出哪些
//	语法字段（server 头、版本字符串、应答码……）？
//
//	Parser **不做**产品判定：不写任何具体产品名，也不给出置信度。
//	产品名、版本切分方式、置信度全部由 rules/*.yaml 决定。
//
// 这样拆分的收益：新增一个厂商只需加一条 YAML；协议语法变化才需要动代码。
package parsers

import "sort"

// Parser 是一个协议语法解析器。
type Parser interface {
	// Name 返回解析器名，用于日志。
	Name() string
	// Protocol 返回其归属的协议枚举（必须与 rules 中的 protocol 一致）。
	Protocol() string
	// Priority 越大越先被调用；仅影响解析顺序，不影响最终仲裁。
	Priority() int
	// Parse 解析 banner。第二个返回值表示「语法上是否属于该协议」。
	// 返回的字段键一律带协议前缀，如 "http.server"，避免跨协议串味。
	Parse(banner []byte) (map[string]string, bool)
}

// All 返回启用的解析器列表（按 Priority 降序，保证遍历确定性）。
func All() []Parser {
	ps := []Parser{
		sshParser{},
		httpParser{},
		mysqlParser{},
		redisParser{},
		ftpParser{},
		tlsParser{},
	}
	sort.SliceStable(ps, func(i, j int) bool {
		if ps[i].Priority() != ps[j].Priority() {
			return ps[i].Priority() > ps[j].Priority()
		}
		return ps[i].Name() < ps[j].Name()
	})
	return ps
}
