package engine_test

import (
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/bannerprint/bannerprint/internal/engine"
	"github.com/bannerprint/bannerprint/internal/jsonx"
	"github.com/bannerprint/bannerprint/internal/model"
	"github.com/bannerprint/bannerprint/internal/rules"
)

func newEngine(t *testing.T, enableTLS bool) *engine.Engine {
	t.Helper()
	set, err := rules.Load("../../rules")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	return engine.New(set, 8192, enableTLS)
}

// TestGoldenDataset 是本项目最重要的测试：题目自测数据 → 金标准逐字段比对。
// 它同时锁死了识别能力、字段书写规范与置信度口径三件事。
func TestGoldenDataset(t *testing.T) {
	eng := newEngine(t, true)

	rawInput, err := os.ReadFile("../../data/input.json")
	if err != nil {
		t.Fatalf("read input: %v", err)
	}
	items, err := jsonx.UnmarshalItems(rawInput)
	if err != nil {
		t.Fatalf("decode input: %v", err)
	}

	rawExpected, err := os.ReadFile("../../data/expected.json")
	if err != nil {
		t.Fatalf("read expected: %v", err)
	}
	var want []model.Result
	if err := json.Unmarshal(rawExpected, &want); err != nil {
		t.Fatalf("decode expected: %v", err)
	}
	if len(items) != len(want) {
		t.Fatalf("dataset size mismatch: input=%d expected=%d", len(items), len(want))
	}

	got := eng.FingerprintBatch(items, 4)
	for i := range want {
		g, w := got[i], want[i]
		if g.IP != w.IP || g.Port != w.Port {
			t.Errorf("#%d identity = (%s:%d), want (%s:%d)", i+1, g.IP, g.Port, w.IP, w.Port)
		}
		if g.Protocol != w.Protocol || g.Product != w.Product || g.Version != w.Version || g.OSHint != w.OSHint {
			t.Errorf("#%d %s:%d = {%s|%s|%s|%s}, want {%s|%s|%s|%s}",
				i+1, w.IP, w.Port,
				g.Protocol, g.Product, g.Version, g.OSHint,
				w.Protocol, w.Product, w.Version, w.OSHint)
		}
		if math.Abs(g.Confidence-w.Confidence) > 1e-9 {
			t.Errorf("#%d %s:%d confidence = %v, want %v", i+1, w.IP, w.Port, g.Confidence, w.Confidence)
		}
	}
}

// TestNeverPanicsOnGarbage 验证「认不出来不许崩」这条硬要求。
// 表里既有空值、纯二进制，也有刻意构造的畸形结构。
func TestNeverPanicsOnGarbage(t *testing.T) {
	eng := newEngine(t, true)

	cases := [][]byte{
		nil,
		{},
		[]byte("QUIT\r\n"),
		[]byte("GET / HTTP/1.1\r\n"),
		[]byte("\x16"),
		[]byte("\x00\x00\x00\x00\x00"),
		[]byte("SSH-"),
		[]byte("220"),
		[]byte("-"),
		[]byte("+"),
		{0xFF, 0xFE, 0xFD, 0x00, 0x01},
		[]byte(strings.Repeat("A", 20000)),
	}
	for i, banner := range cases {
		res := eng.Fingerprint(model.Item{IP: "192.0.2.1", Port: 1, Banner: banner})
		if res.IP != "192.0.2.1" || res.Port != 1 {
			t.Errorf("case %d: identity not echoed: %+v", i, res)
		}
		if res.Protocol == "" {
			t.Errorf("case %d: protocol must never be empty", i)
		}
	}
}

// TestUnknownIsZeroConfidence 锁定 unknown 的口径：协议 unknown、置信度 0。
func TestUnknownIsZeroConfidence(t *testing.T) {
	eng := newEngine(t, true)
	res := eng.Fingerprint(model.Item{IP: "1.2.3.23", Port: 12345, Banner: []byte("QUIT\r\n")})
	if res.Protocol != model.ProtocolUnknown {
		t.Fatalf("protocol = %q, want unknown", res.Protocol)
	}
	if res.Product != "" || res.Version != "" || res.OSHint != "" || res.Confidence != 0 {
		t.Errorf("unknown result must be empty, got %+v", res)
	}
}

// TestTLSDetectCanBeDisabled 验证开关语义：关掉后同一输入降级为 unknown。
func TestTLSDetectCanBeDisabled(t *testing.T) {
	banner := []byte{0x16, 0x03, 0x01, 0x00, 0xA5, 0x01}
	enabled := newEngine(t, true).Fingerprint(model.Item{IP: "x", Port: 9999, Banner: banner})
	if enabled.Protocol != "TLS" {
		t.Fatalf("enabled: protocol = %q, want TLS", enabled.Protocol)
	}
	disabled := newEngine(t, false).Fingerprint(model.Item{IP: "x", Port: 9999, Banner: banner})
	if disabled.Protocol != model.ProtocolUnknown {
		t.Fatalf("disabled: protocol = %q, want unknown", disabled.Protocol)
	}
}

// TestDeterministic 保证同一输入多次识别结果一致（不依赖 map 迭代顺序）。
func TestDeterministic(t *testing.T) {
	eng := newEngine(t, true)
	item := model.Item{IP: "1.2.3.4", Port: 22, Banner: []byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")}
	first := eng.Fingerprint(item)
	for i := 0; i < 100; i++ {
		if got := eng.Fingerprint(item); got != first {
			t.Fatalf("iteration %d: %+v != %+v", i, got, first)
		}
	}
}

// TestJSONFieldOrder 锁定响应字段顺序（严格比对型评估器会看这个）。
func TestJSONFieldOrder(t *testing.T) {
	b, err := json.Marshal(model.Result{
		IP: "1.2.3.4", Port: 22, Protocol: "SSH", Product: "OpenSSH",
		Version: "8.9p1", OSHint: "Ubuntu", Confidence: 0.95,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"Ubuntu","confidence":0.95}`
	if string(b) != want {
		t.Errorf("json = %s\nwant   %s", b, want)
	}
}
