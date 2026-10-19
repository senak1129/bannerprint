package rules_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bannerprint/bannerprint/internal/rules"
)

// repoRulesDir 指向仓库根的真实规则目录（测试从包目录出发）。
const repoRulesDir = "../../rules"

// TestLoadRepositoryRules 确认仓库里的规则能被完整加载，且每个协议都有规则。
// 这条测试的价值：任何一条 YAML 手滑都会让服务起不来，必须在 CI 阶段暴露。
func TestLoadRepositoryRules(t *testing.T) {
	set, err := rules.Load(repoRulesDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if set.Count() < 16 {
		t.Errorf("rule count = %d, want >= 16", set.Count())
	}
	for _, protocol := range []string{"SSH", "HTTP", "MySQL", "Redis", "FTP", "TLS"} {
		if n := set.ProtocolCount(protocol); n == 0 {
			t.Errorf("protocol %s has no rules", protocol)
		}
	}
	if set.Stats.Files == 0 || set.Stats.Source == "" {
		t.Errorf("unexpected stats: %+v", set.Stats)
	}
}

// TestLoadMissingDirFallsBackToEmbedded 确认「外部规则目录不存在」不是错误：
// 本机 go run 时通常没有 /etc/bannerprint/rules.d，此时应使用内置规则。
func TestLoadMissingDirFallsBackToEmbedded(t *testing.T) {
	set, err := rules.Load(filepath.Join(t.TempDir(), "not-exist"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if set.Stats.Source != "embedded" {
		t.Errorf("source = %q, want embedded", set.Stats.Source)
	}
	if set.Count() == 0 {
		t.Error("embedded rules not loaded")
	}
}

// TestDuplicateIDRejected 验证启动强校验：重复 id 必须让服务拒绝启动，
// 否则仲裁结果会依赖加载顺序，变得不可预测。
func TestDuplicateIDRejected(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "dup.yaml", `
version: 1
protocol: HTTP
rules:
  - id: dup.rule
    match:
      source: field
      field: http.server
      regex: '^a$'
    fields: {product: 'a'}
    confidence: {base: 0.5}
  - id: dup.rule
    match:
      source: field
      field: http.server
      regex: '^b$'
    fields: {product: 'b'}
    confidence: {base: 0.5}
`)
	if _, err := rules.Load(dir); err == nil {
		t.Fatal("expected duplicate id error, got nil")
	}
}

// TestInvalidRegexRejected 验证非法正则不会拖到运行期才炸。
func TestInvalidRegexRejected(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "bad.yaml", `
version: 1
protocol: HTTP
rules:
  - id: bad.regex
    match:
      source: field
      field: http.server
      regex: '([unclosed'
    fields: {product: 'x'}
    confidence: {base: 0.5}
`)
	if _, err := rules.Load(dir); err == nil {
		t.Fatal("expected regex compile error, got nil")
	}
}

// TestMatchHTTPField 验证「字段来源规则」的完整链路：正则捕获 → 模板渲染 → 置信度。
func TestMatchHTTPField(t *testing.T) {
	set, err := rules.Load(repoRulesDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	cands := set.Match("HTTP", nil, map[string]string{
		"http.status_line": "HTTP/1.1 200 OK",
		"http.server":      "nginx/1.18.0 (Ubuntu)",
	})
	if len(cands) == 0 {
		t.Fatal("no candidates")
	}
	// 取最高分（engine 的仲裁逻辑在这里被简化复用）
	best := cands[0]
	for _, c := range cands[1:] {
		if c.Confidence > best.Confidence {
			best = c
		}
	}
	if best.Product != "nginx" || best.Version != "1.18.0" || best.OSHint != "Ubuntu" {
		t.Errorf("got %+v", best)
	}
	if best.Confidence != 0.9 {
		t.Errorf("confidence = %v, want 0.9", best.Confidence)
	}
}

// TestMatchNoVersionDropsConfidence 验证 if_empty 覆盖生效：
// 只有产品没有版本时，置信度必须降档，避免「猜出来的高分」。
func TestMatchNoVersionDropsConfidence(t *testing.T) {
	set, err := rules.Load(repoRulesDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	cands := set.Match("HTTP", nil, map[string]string{
		"http.status_line": "HTTP/1.1 200 OK",
		"http.server":      "nginx",
	})
	for _, c := range cands {
		if c.Product == "nginx" {
			if c.Version != "" {
				t.Errorf("version = %q, want empty", c.Version)
			}
			if c.Confidence != 0.8 {
				t.Errorf("confidence = %v, want 0.8", c.Confidence)
			}
			return
		}
	}
	t.Fatal("nginx candidate not found")
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}
