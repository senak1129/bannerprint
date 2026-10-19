package parsers

import "strings"

// respPrefixes 是 RESP 协议允许的行首标记：
//
//	+ 简单字符串   - 错误   : 整数   $ 批量字符串   * 数组
var respPrefixes = map[byte]bool{'+': true, '-': true, ':': true, '$': true, '*': true}

type redisParser struct{}

func (redisParser) Name() string     { return "redis" }
func (redisParser) Protocol() string { return "Redis" }
func (redisParser) Priority() int    { return 80 }

// Parse 只做语法判定：行首是 RESP 标记，且后面还有内容。
//
// 刻意不在这里判断 "ERR"/"NOAUTH" 等关键字 —— 那是产品知识，写在 rules/redis.yaml。
// 因此像 "-bash: command not found" 这样的文本也会通过本 Parser，
// 但不会命中任何 Redis 规则，最终仍然输出 unknown（误报被规则层挡住）。
func (redisParser) Parse(banner []byte) (map[string]string, bool) {
	if len(banner) < 2 || !respPrefixes[banner[0]] {
		return nil, false
	}
	line := banner
	if i := indexByte(banner, '\n'); i >= 0 {
		line = banner[:i]
	}
	reply := strings.TrimRight(string(line), "\r")
	if len(reply) < 2 {
		return nil, false
	}
	return map[string]string{
		"redis.prefix": string(reply[0]),
		"redis.reply":  reply,
	}, true
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}
