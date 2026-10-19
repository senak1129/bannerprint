package rules

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	ruledata "github.com/bannerprint/bannerprint/rules"
)

// Load 加载规则集合。
//
// 两级来源（对应 spec §7.2）：
//  1. 编译期内置（go:embed rules/*.yaml）—— 保证镜像自包含，无外部依赖也能跑；
//  2. 运行时目录（RULES_DIR，compose 以 :ro 挂载）—— 同名文件**整体替换**，
//     新文件追加。这让「改规则」无需重新构建镜像，也让评估者能直接验证解耦。
//
// 任何一条规则不合法都会导致整体失败（fail fast）：带着半套规则启动会输出
// 看似正常、实则漏报的结果，比直接起不来更危险。
func Load(dir string) (*Set, error) {
	files := make(map[string][]byte)

	entries, err := ruledata.FS.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("rules: read embedded rules: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !isYAML(e.Name()) {
			continue
		}
		b, err := ruledata.FS.ReadFile(e.Name())
		if err != nil {
			return nil, fmt.Errorf("rules: read embedded %s: %w", e.Name(), err)
		}
		files[e.Name()] = b
	}

	source := "embedded"
	if dir != "" {
		ents, err := os.ReadDir(dir)
		switch {
		case err == nil:
			overridden := 0
			for _, e := range ents {
				if e.IsDir() || !isYAML(e.Name()) {
					continue
				}
				b, err := os.ReadFile(filepath.Join(dir, e.Name()))
				if err != nil {
					return nil, fmt.Errorf("rules: read %s: %w", e.Name(), err)
				}
				files[e.Name()] = b // 同名整体替换
				overridden++
			}
			if overridden > 0 {
				source = "embedded+dir"
			}
		case errors.Is(err, fs.ErrNotExist):
			// 目录不存在：允许，仅使用内置规则（本机 go run 的常见情形）
		default:
			return nil, fmt.Errorf("rules: read dir %q: %w", dir, err)
		}
	}

	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names) // 固定顺序 → 匹配结果确定性

	set := &Set{
		byProtocol: make(map[string][]Rule, len(allowedProtocols)),
		Stats: Stats{
			Files:    len(names),
			LoadedAt: time.Now().UTC(),
			Source:   source,
		},
	}

	seen := make(map[string]string, 32) // ruleID → 文件名
	for _, name := range names {
		compiled, err := compileFile(name, files[name])
		if err != nil {
			return nil, err
		}
		for _, r := range compiled {
			if prev, dup := seen[r.ID]; dup {
				return nil, fmt.Errorf("rules: duplicate rule id %q in %s (first seen in %s)", r.ID, name, prev)
			}
			seen[r.ID] = name
			set.byProtocol[r.Protocol] = append(set.byProtocol[r.Protocol], r)
			set.Stats.Rules++
		}
	}
	if set.Stats.Rules == 0 {
		return nil, errors.New("rules: no rules loaded")
	}
	return set, nil
}

func isYAML(name string) bool {
	return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")
}

func compileFile(name string, data []byte) ([]Rule, error) {
	var rf rawFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("rules: parse %s: %w", name, err)
	}
	if rf.Version != 1 {
		return nil, fmt.Errorf("rules: %s: unsupported version %d (want 1)", name, rf.Version)
	}
	if !allowedProtocols[rf.Protocol] {
		return nil, fmt.Errorf("rules: %s: unknown protocol %q", name, rf.Protocol)
	}
	out := make([]Rule, 0, len(rf.Rules))
	for i, rr := range rf.Rules {
		r, err := compileRule(rf.Protocol, name, rr)
		if err != nil {
			return nil, fmt.Errorf("rules: %s rule #%d (%s): %w", name, i+1, rr.ID, err)
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("rules: %s: no rules defined", name)
	}
	return out, nil
}

func compileRule(protocol, file string, rr rawRule) (Rule, error) {
	if strings.TrimSpace(rr.ID) == "" {
		return Rule{}, errors.New("missing id")
	}
	if rr.Priority < 0 || rr.Priority > 1000 {
		return Rule{}, fmt.Errorf("priority %d out of range [0,1000]", rr.Priority)
	}
	if rr.Priority == 0 {
		rr.Priority = 50 // 缺省优先级
	}
	if rr.Match.Source != "raw" && rr.Match.Source != "field" {
		return Rule{}, fmt.Errorf("match.source must be raw or field, got %q", rr.Match.Source)
	}
	if rr.Match.Source == "field" && rr.Match.Field == "" {
		return Rule{}, errors.New("match.field is required when source=field")
	}
	re, err := regexp.Compile(rr.Match.Regex)
	if err != nil {
		return Rule{}, fmt.Errorf("invalid regex: %w", err)
	}
	if len(re.SubexpNames()) > 9 { // 1 个整体 + 最多 8 个捕获组
		return Rule{}, fmt.Errorf("too many capture groups (%d, max 8)", len(re.SubexpNames())-1)
	}
	if rr.Confidence.Base <= 0 || rr.Confidence.Base >= 1 {
		return Rule{}, fmt.Errorf("confidence.base %v out of range (0,1)", rr.Confidence.Base)
	}
	for k, v := range rr.Confidence.IfEmpty {
		if v <= 0 || v >= 1 {
			return Rule{}, fmt.Errorf("confidence.if_empty[%s] %v out of range (0,1)", k, v)
		}
	}
	product, err := parseTpl(rr.Fields["product"])
	if err != nil {
		return Rule{}, fmt.Errorf("fields.product template: %w", err)
	}
	version, err := parseTpl(rr.Fields["version"])
	if err != nil {
		return Rule{}, fmt.Errorf("fields.version template: %w", err)
	}
	oshint, err := parseTpl(rr.Fields["os_hint"])
	if err != nil {
		return Rule{}, fmt.Errorf("fields.os_hint template: %w", err)
	}
	return Rule{
		ID:         rr.ID,
		Protocol:   protocol,
		Priority:   rr.Priority,
		Source:     rr.Match.Source,
		Field:      rr.Match.Field,
		re:         re,
		tplProduct: product,
		tplVersion: version,
		tplOS:      oshint,
		base:       rr.Confidence.Base,
		ifEmpty:    rr.Confidence.IfEmpty,
		file:       file,
	}, nil
}
