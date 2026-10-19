package parsers

import "regexp"

// ftpReplyRe 匹配 RFC 959 的三位应答码：
//
//	220 <Product> 1.2.3 Server      → "220" + 空格 + 文本
//	220-<Product> ready             → "220" + 连字符 + 文本（多行应答的首行）
var ftpReplyRe = regexp.MustCompile(`^(\d{3})([ -])([^\r\n]*)`)

type ftpParser struct{}

func (ftpParser) Name() string     { return "ftp" }
func (ftpParser) Protocol() string { return "FTP" }
func (ftpParser) Priority() int    { return 90 }

// Parse 抽出应答码与文本。
// 具体产品名与版本切分属于知识，放在 rules/ftp.yaml。
func (ftpParser) Parse(banner []byte) (map[string]string, bool) {
	m := ftpReplyRe.FindSubmatch(banner)
	if m == nil {
		return nil, false
	}
	return map[string]string{
		"ftp.code": string(m[1]),
		"ftp.text": string(m[3]),
	}, true
}
