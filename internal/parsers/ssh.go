package parsers

import "regexp"

// sshBannerRe 匹配 RFC 4253 §4.2 的标识串：
//
//	SSH-protoversion-softwareversion[ SP comments]
//
// 使用 (?m)^ 而非 ^：真实环境中 banner 前面可能夹着网关/蜜罐注入的噪声行，
// 协议行未必在第一个字节。
var sshBannerRe = regexp.MustCompile(`(?m)^SSH-(\d\.\d+)-([^\s]+)(?:[ \t]+([^\r\n]*))?`)

type sshParser struct{}

func (sshParser) Name() string     { return "ssh" }
func (sshParser) Protocol() string { return "SSH" }
func (sshParser) Priority() int    { return 100 }

// Parse 抽出协议版本、软件标识、注释三部分。
//
// 注意：这里**不**切分软件标识（如 "Product_1.2.3"），因为「下划线前是产品、
// 后面是版本」是厂商书写习惯（知识），不是 SSH 协议语法 —— 该切分由
// rules/ssh.yaml 完成。
func (sshParser) Parse(banner []byte) (map[string]string, bool) {
	m := sshBannerRe.FindSubmatch(banner)
	if m == nil {
		return nil, false
	}
	fields := map[string]string{
		"ssh.protoversion": string(m[1]),
		"ssh.software":     string(m[2]),
	}
	if len(m) > 3 && len(m[3]) > 0 {
		fields["ssh.comment"] = string(m[3])
	}
	return fields, true
}
