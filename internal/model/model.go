// Package model 定义系统的输入与输出数据结构。
//
// 设计约束（对应 spec §5）：
//   - Result 的字段声明顺序即 JSON 序列化顺序，必须与接口契约完全一致：
//     ip → port → protocol → product → version → os_hint → confidence。
//   - Banner 在内部一律使用 []byte：扫描原始数据可能含 NUL、非 UTF-8 字节，
//     一旦经过 string 的 UTF-8 校验或 JSON 重新编码就会被破坏（MySQL 握手包即为典型）。
package model

// Item 是一条待识别的扫描原始数据。
type Item struct {
	IP     string // 目标 IP，原样回显，不做合法性校验（避免脏数据导致整批失败）
	Port   int    // 目标端口，仅作候选排序的弱先验，不参与协议硬判定
	Banner []byte // 服务返回的原始字节（已从 JSON 转义中解码）
}

// Candidate 是「某个 Parser + 某条 Rule」产生的候选识别结果。
// 一批输入可能产生多个候选（例如 banner 同时具备 FTP 与 HTTP 特征），
// 由 engine 依据置信度→优先级→规则 ID 的顺序仲裁出唯一结果。
type Candidate struct {
	Protocol   string  // 协议规范名（SSH/HTTP/MySQL/Redis/FTP/TLS）
	Product    string  // 产品规范名，未知为空串
	Version    string  // 版本原样字符串，未知为空串
	OSHint     string  // 操作系统线索，未知为空串
	Confidence float64 // 置信度 0~1
	Priority   int     // 规则优先级，仅用于同分仲裁
	RuleID     string  // 命中的规则 ID，用于日志与 ?explain 调试
}

// Result 是对外输出的识别结果，字段顺序即 JSON 键顺序。
type Result struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

// ProtocolUnknown 是「无法识别」的规范取值。
// 注意：认不出来不是错误，永远以 200 + unknown 返回（对应 spec §4.2）。
const ProtocolUnknown = "unknown"

// Unknown 构造一条兜底结果：protocol=unknown，其余字段为空，置信度 0。
func Unknown(ip string, port int) Result {
	return Result{
		IP:         ip,
		Port:       port,
		Protocol:   ProtocolUnknown,
		Product:    "",
		Version:    "",
		OSHint:     "",
		Confidence: 0,
	}
}
