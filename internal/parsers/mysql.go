package parsers

import "regexp"

// mysqlVersionRe 校验握手包里的版本字符串形态（"8.0.32"、"5.7.42-log"）。
// 只要求形如 x.y[.z...] 的前缀，避免把任意以 NUL 分隔的二进制串误判为 MySQL。
var mysqlVersionRe = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)*(?:[-~][0-9A-Za-z.\-]+)?`)

type mysqlParser struct{}

func (mysqlParser) Name() string     { return "mysql" }
func (mysqlParser) Protocol() string { return "MySQL" }
func (mysqlParser) Priority() int    { return 100 }

// Parse 解析 MySQL Initial Handshake Packet (Protocol::HandshakeV10)：
//
//	[3B payload_length LE][1B sequence_id][1B protocol_version=0x0A]
//	[NUL-terminated server_version][4B thread_id]...
//
// 两个工程细节：
//  1. 必须按字节处理。若先做 UTF-8 校验或 string 转换，0x00 之后的二进制
//     段会干扰判断，部分扫描器还会把不可打印字节转成 \xNN 文本。
//  2. payload_length 常与真实长度不符（裁剪过的 banner 尤其常见），
//     因此固定位置 4 不匹配时，再尝试位置 5（长度字段少一字节的情形）。
func (mysqlParser) Parse(banner []byte) (map[string]string, bool) {
	if len(banner) < 7 {
		return nil, false
	}

	idx := -1
	switch {
	case banner[4] == 0x0A:
		idx = 5
	case banner[5] == 0x0A:
		idx = 6
	default:
		return nil, false
	}

	end := idx
	for end < len(banner) && banner[end] != 0x00 {
		end++
	}
	version := string(banner[idx:end])
	if !mysqlVersionRe.MatchString(version) {
		return nil, false
	}
	return map[string]string{
		"mysql.server_version":   version,
		"mysql.protocol_version": "10",
	}, true
}
