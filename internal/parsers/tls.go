package parsers

type tlsParser struct{}

func (tlsParser) Name() string     { return "tls" }
func (tlsParser) Protocol() string { return "TLS" }
func (tlsParser) Priority() int    { return 95 }

// Parse 识别 TLS record 头：
//
//	0x16            ContentType = Handshake
//	0x03 0x00–0x04  ProtocolVersion (SSL3.0 / TLS1.0–1.3 record 层)
//
// 只判定「这是 TLS 握手记录」，不解析 ClientHello/ServerHello 内部结构：
// 没有完整报文时做更深解析只会带来误判。协议判定在此，产品与置信度在
// rules/tls.yaml（当前输出 TLS/0.60，可用 ENABLE_TLS_DETECT=0 关闭）。
func (tlsParser) Parse(banner []byte) (map[string]string, bool) {
	if len(banner) < 3 {
		return nil, false
	}
	if banner[0] != 0x16 || banner[1] != 0x03 || banner[2] > 0x04 {
		return nil, false
	}
	return map[string]string{"tls.record": "handshake"}, true
}
