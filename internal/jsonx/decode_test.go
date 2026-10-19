package jsonx

import (
	"bytes"
	"errors"
	"testing"

	"github.com/bannerprint/bannerprint/internal/model"
)

// TestUnmarshalItems 覆盖真实扫描数据里出现过的各种「非法但常见」写法。
// 核心断言：任何一条脏数据都不能让整批解析失败。
func TestUnmarshalItems(t *testing.T) {
	// 裸控制字符（0x00）直接出现在 JSON 字符串内部
	rawControl := "[{\"ip\":\"c\",\"port\":3,\"banner\":\"A\x00B\"}]"

	tests := []struct {
		name    string
		input   string
		want    []model.Item
		wantErr bool
	}{
		{
			name:  "standard escapes",
			input: `[{"ip":"1.2.3.5","port":80,"banner":"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"}]`,
			want: []model.Item{{
				IP:     "1.2.3.5",
				Port:   80,
				Banner: []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"),
			}},
		},
		{
			// 本次任务最关键的一条：\xNN 不是合法 JSON，标准库会直接报错
			name:  "non-standard hex escape becomes raw byte",
			input: `[{"ip":"1.2.3.7","port":3306,"banner":"J\x00\x00\x00\n8.0.32\x00"}]`,
			want: []model.Item{{
				IP:     "1.2.3.7",
				Port:   3306,
				Banner: []byte{'J', 0x00, 0x00, 0x00, 0x0A, '8', '.', '0', '.', '3', '2', 0x00},
			}},
		},
		{
			name:  "unicode escape",
			input: `[{"ip":"a","port":1,"banner":"J\u0000\u0000\u00008.0.32\u0000"}]`,
			want: []model.Item{{
				IP:     "a",
				Port:   1,
				Banner: []byte{'J', 0, 0, 0, '8', '.', '0', '.', '3', '2', 0},
			}},
		},
		{
			name:  "raw control characters tolerated",
			input: rawControl,
			want:  []model.Item{{IP: "c", Port: 3, Banner: []byte{'A', 0x00, 'B'}}},
		},
		{
			name:  "ndjson",
			input: "{\"ip\":\"a\",\"port\":1,\"banner\":\"x\"}\n{\"ip\":\"b\",\"port\":2,\"banner\":\"y\"}\n",
			want: []model.Item{
				{IP: "a", Port: 1, Banner: []byte("x")},
				{IP: "b", Port: 2, Banner: []byte("y")},
			},
		},
		{
			// 字段缺失/类型不符：降级为零值，但条数必须保持 1:1
			name:  "non-object element degrades",
			input: `[1,{"ip":"b","port":"22","banner":"z"}]`,
			want: []model.Item{
				{},
				{IP: "b", Port: 22, Banner: []byte("z")},
			},
		},
		{name: "empty body", input: ``, wantErr: true},
		{name: "empty array", input: `[ ]`, wantErr: true},
		{name: "trailing comma", input: `[{"ip":"a",}]`, wantErr: true},
		{name: "single quotes", input: `[{'ip':'a'}]`, wantErr: true},
		{name: "unterminated string", input: `[{"ip":"a}]`, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := UnmarshalItems([]byte(tc.input))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got items=%v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("item count = %d, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if got[i].IP != tc.want[i].IP || got[i].Port != tc.want[i].Port {
					t.Errorf("item[%d] = (%q,%d), want (%q,%d)", i, got[i].IP, got[i].Port, tc.want[i].IP, tc.want[i].Port)
				}
				if !bytes.Equal(got[i].Banner, tc.want[i].Banner) {
					t.Errorf("item[%d] banner = %v, want %v", i, got[i].Banner, tc.want[i].Banner)
				}
			}
		})
	}
}

// TestUnmarshalItemsEmptySentinel 确认空输入返回可判别的哨兵错误，
// 上层 API 依赖它区分 400 empty_batch 与 400 invalid_json。
func TestUnmarshalItemsEmptySentinel(t *testing.T) {
	if _, err := UnmarshalItems(nil); !errors.Is(err, ErrEmpty) {
		t.Fatalf("want ErrEmpty, got %v", err)
	}
}
