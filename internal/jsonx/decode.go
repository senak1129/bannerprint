// Package jsonx 实现宽松（lenient）的 JSON 解码，专用于解析网络扫描原始数据。
//
// 为什么不用 encoding/json（对应 spec §4.4）：
//
//	真实扫描器产出的 banner 常被写成 "J\x00\x00\x00\n8.0.32\x00" 这种形式。
//	`\xNN` 不是合法 JSON 转义，encoding/json 会直接返回语法错误，
//	导致「一条脏数据 → 整批 400」——这正是题目明确禁止的失败模式。
//
// 本包逐字节扫描字符串 token，在标准转义之外额外接受：
//   - `\xNN`：解码为**单个原始字节**（注意：不能先转成 \u00NN，否则再编码为
//     UTF-8 会把 0xA5 变成 C2 A5 两个字节，TLS/MySQL 等二进制特征随即失效）；
//   - 裸控制字符（0x00–0x1F 直接出现在字符串内）；
//   - UTF-16 代理对（\uD83D\uDE00 → 单个 rune）。
//
// 仍然拒绝：单引号字符串、尾随逗号、注释——这些会产生歧义，宁可报错也不猜。
package jsonx

import (
	"errors"
	"fmt"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/bannerprint/bannerprint/internal/model"
)

// ErrEmpty 表示输入为空、空数组或空 NDJSON。
// 上层 API 依据它返回 400（空批次属于客户端错误，而非服务端故障）。
var ErrEmpty = errors.New("jsonx: empty input")

// UnmarshalItems 解析一批扫描数据。
//
// 自动判别两种顶层形态：
//   - JSON 数组：`[{...},{...}]`
//   - NDJSON：每行一个对象（扫描器流式落盘的常见形态）
//
// 单条记录字段缺失/类型不符不会返回错误，而是降级为零值 Item，
// 以保证「输出与输入严格 1:1」这一契约不因脏数据被破坏。
func UnmarshalItems(data []byte) ([]model.Item, error) {
	d := &decoder{data: data}
	d.skipSpace()
	if d.pos >= len(d.data) {
		return nil, ErrEmpty
	}

	// 顶层数组
	if d.data[d.pos] == '[' {
		arr, err := d.parseArray()
		if err != nil {
			return nil, err
		}
		d.skipSpace()
		if d.pos < len(d.data) {
			return nil, d.errf("trailing data after top-level array")
		}
		if len(arr) == 0 {
			return nil, ErrEmpty
		}
		items := make([]model.Item, 0, len(arr))
		for _, v := range arr {
			items = append(items, toItem(v))
		}
		return items, nil
	}

	// NDJSON：连续对象，以空白分隔
	var items []model.Item
	for {
		d.skipSpace()
		if d.pos >= len(d.data) {
			break
		}
		if d.data[d.pos] != '{' {
			return nil, d.errf("expected object for NDJSON input")
		}
		v, err := d.parseObject()
		if err != nil {
			return nil, err
		}
		items = append(items, toItem(v))
	}
	if len(items) == 0 {
		return nil, ErrEmpty
	}
	return items, nil
}

// decoder 是一个最小化的递归下降解析器，仅覆盖 JSON 值语法 + 上述宽松扩展。
type decoder struct {
	data []byte
	pos  int
}

func (d *decoder) errf(format string, args ...any) error {
	return fmt.Errorf("jsonx: offset %d: %s", d.pos, fmt.Sprintf(format, args...))
}

// skipSpace 跳过 JSON 空白。注意换行也在此跳过，NDJSON 依赖该行为。
func (d *decoder) skipSpace() {
	for d.pos < len(d.data) {
		switch d.data[d.pos] {
		case ' ', '\t', '\r', '\n':
			d.pos++
		default:
			return
		}
	}
}

func (d *decoder) parseValue() (any, error) {
	d.skipSpace()
	if d.pos >= len(d.data) {
		return nil, d.errf("unexpected end of input")
	}
	switch c := d.data[d.pos]; {
	case c == '{':
		return d.parseObject()
	case c == '[':
		return d.parseArray()
	case c == '"':
		return d.parseString()
	case c == 't':
		return nil, d.parseLiteral("true", true)
	case c == 'f':
		return nil, d.parseLiteral("false", false)
	case c == 'n':
		return nil, d.parseLiteral("null", nil)
	case c == '-' || (c >= '0' && c <= '9'):
		return d.parseNumber()
	default:
		return nil, d.errf("unexpected character %q", c)
	}
}

func (d *decoder) parseLiteral(lit string, val any) error {
	if len(d.data)-d.pos < len(lit) || string(d.data[d.pos:d.pos+len(lit)]) != lit {
		return d.errf("invalid literal, want %q", lit)
	}
	d.pos += len(lit)
	return nil
}

func (d *decoder) parseObject() (map[string]any, error) {
	if d.data[d.pos] != '{' {
		return nil, d.errf("expected '{'")
	}
	d.pos++
	obj := make(map[string]any)
	d.skipSpace()
	if d.pos < len(d.data) && d.data[d.pos] == '}' {
		d.pos++
		return obj, nil // 空对象合法
	}
	for {
		d.skipSpace()
		if d.pos >= len(d.data) || d.data[d.pos] != '"' {
			return nil, d.errf("expected object key")
		}
		key, err := d.parseString()
		if err != nil {
			return nil, err
		}
		d.skipSpace()
		if d.pos >= len(d.data) || d.data[d.pos] != ':' {
			return nil, d.errf("expected ':' after key %q", key)
		}
		d.pos++
		val, err := d.parseValue()
		if err != nil {
			return nil, err
		}
		obj[key] = val
		d.skipSpace()
		if d.pos >= len(d.data) {
			return nil, d.errf("unterminated object")
		}
		switch d.data[d.pos] {
		case ',':
			d.pos++
			d.skipSpace()
			// 尾随逗号：明确拒绝，不做猜测
			if d.pos < len(d.data) && d.data[d.pos] == '}' {
				return nil, d.errf("trailing comma in object")
			}
		case '}':
			d.pos++
			return obj, nil
		default:
			return nil, d.errf("expected ',' or '}' in object")
		}
	}
}

func (d *decoder) parseArray() ([]any, error) {
	if d.data[d.pos] != '[' {
		return nil, d.errf("expected '['")
	}
	d.pos++
	arr := make([]any, 0, 8)
	d.skipSpace()
	if d.pos < len(d.data) && d.data[d.pos] == ']' {
		d.pos++
		return arr, nil
	}
	for {
		val, err := d.parseValue()
		if err != nil {
			return nil, err
		}
		arr = append(arr, val)
		d.skipSpace()
		if d.pos >= len(d.data) {
			return nil, d.errf("unterminated array")
		}
		switch d.data[d.pos] {
		case ',':
			d.pos++
			d.skipSpace()
			if d.pos < len(d.data) && d.data[d.pos] == ']' {
				return nil, d.errf("trailing comma in array")
			}
		case ']':
			d.pos++
			return arr, nil
		default:
			return nil, d.errf("expected ',' or ']' in array")
		}
	}
}

// parseString 解码字符串。返回值是「字节安全」的 Go string：
// 每个 \xNN 精确对应一个字节，不做任何字符集转换。
func (d *decoder) parseString() (string, error) {
	if d.data[d.pos] != '"' {
		return "", d.errf("expected '\"'")
	}
	d.pos++
	out := make([]byte, 0, 64)
	for d.pos < len(d.data) {
		c := d.data[d.pos]
		switch c {
		case '"':
			d.pos++
			return string(out), nil
		case '\\':
			d.pos++
			if d.pos >= len(d.data) {
				return "", d.errf("unexpected end after backslash")
			}
			e := d.data[d.pos]
			switch e {
			case '"':
				out = append(out, '"')
				d.pos++
			case '\\':
				out = append(out, '\\')
				d.pos++
			case '/':
				out = append(out, '/')
				d.pos++
			case 'b':
				out = append(out, '\b')
				d.pos++
			case 'f':
				out = append(out, '\f')
				d.pos++
			case 'n':
				out = append(out, '\n')
				d.pos++
			case 'r':
				out = append(out, '\r')
				d.pos++
			case 't':
				out = append(out, '\t')
				d.pos++
			case 'u':
				r, err := d.readHexRune()
				if err != nil {
					return "", err
				}
				// 代理对：高代理后必须紧跟 \uDC00–\uDFFF
				if r >= 0xD800 && r <= 0xDBFF && d.peekUnicodeEscape() {
					d.pos += 2 // 跳过 "\u"
					lo, err := d.readHex4Raw()
					if err != nil {
						return "", err
					}
					if lo >= 0xDC00 && lo <= 0xDFFF {
						out = utf8.AppendRune(out, utf16.DecodeRune(rune(r), rune(lo)))
					} else {
						// 非法配对：各自按替换符处理，保证不中断整批
						out = utf8.AppendRune(out, utf8.RuneError)
						out = utf8.AppendRune(out, rune(lo))
					}
				} else {
					out = utf8.AppendRune(out, rune(r))
				}
			case 'x':
				// 宽松扩展：\xNN → 单个原始字节
				b, err := d.readHexByte()
				if err != nil {
					return "", err
				}
				out = append(out, b)
			default:
				return "", d.errf("invalid escape \\%c", e)
			}
		default:
			// 裸控制字符/任意字节：原样保留（宽松模式）
			out = append(out, c)
			d.pos++
		}
	}
	return "", d.errf("unterminated string")
}

// readHexRune 处理 "u" 之后的 4 位十六进制。
func (d *decoder) readHexRune() (uint32, error) {
	d.pos++ // 跳过 'u'
	return d.readHex4Raw()
}

func (d *decoder) readHex4Raw() (uint32, error) {
	if d.pos+4 > len(d.data) {
		return 0, d.errf("truncated \\u escape")
	}
	v, err := strconv.ParseUint(string(d.data[d.pos:d.pos+4]), 16, 32)
	if err != nil {
		return 0, d.errf("invalid \\u escape %q", string(d.data[d.pos:min(d.pos+4, len(d.data))]))
	}
	d.pos += 4
	return uint32(v), nil
}

// readHexByte 处理 "x" 之后的 2 位十六进制，返回原始字节。
func (d *decoder) readHexByte() (byte, error) {
	d.pos++ // 跳过 'x'
	if d.pos+2 > len(d.data) {
		return 0, d.errf("truncated \\x escape")
	}
	v, err := strconv.ParseUint(string(d.data[d.pos:d.pos+2]), 16, 8)
	if err != nil {
		return 0, d.errf("invalid \\x escape %q", string(d.data[d.pos:min(d.pos+2, len(d.data))]))
	}
	d.pos += 2
	return byte(v), nil
}

// peekUnicodeEscape 判断当前位置是否为 `\u`，用于代理对前瞻。
func (d *decoder) peekUnicodeEscape() bool {
	return d.pos+1 < len(d.data) && d.data[d.pos] == '\\' && d.data[d.pos+1] == 'u'
}

func (d *decoder) parseNumber() (float64, error) {
	start := d.pos
	for d.pos < len(d.data) {
		c := d.data[d.pos]
		if (c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E' {
			d.pos++
			continue
		}
		break
	}
	f, err := strconv.ParseFloat(string(d.data[start:d.pos]), 64)
	if err != nil {
		return 0, d.errf("invalid number %q", string(d.data[start:d.pos]))
	}
	return f, nil
}

// toItem 把解析出的 map 映射为 Item。
//
// 容错策略（对应 spec §4.2「单条字段缺失降级」）：
//   - 非对象元素 → 零值 Item（仍然占位，保证 1:1）
//   - ip 非字符串 → ""
//   - port 为数字或数字字符串 → int，其余 → 0
//   - banner 缺失/非字符串 → 空字节串（引擎会返回 unknown）
func toItem(v any) model.Item {
	m, ok := v.(map[string]any)
	if !ok {
		return model.Item{}
	}
	var it model.Item
	if s, ok := m["ip"].(string); ok {
		it.IP = s
	}
	switch p := m["port"].(type) {
	case float64:
		it.Port = int(p)
	case string:
		if n, err := strconv.Atoi(p); err == nil {
			it.Port = n
		}
	}
	if s, ok := m["banner"].(string); ok {
		it.Banner = []byte(s)
	}
	return it
}
