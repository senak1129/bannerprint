// Package engine 是识别流水线的编排层（对应 spec §7.1）：
//
//	Normalize → Probe(parsers) → Match(rules) → Resolve(仲裁) → Result
//
// 三条不可妥协的工程约束：
//  1. 纯函数：Fingerprint 不读时间、不发起网络请求、不依赖全局可变状态，
//     因此可对任意字节流做表驱动测试与 fuzz。
//  2. 永不 panic：单条输入在独立 recover 边界内处理，异常降级为 unknown，
//     绝不让一条脏数据打断整批（题目硬性要求）。
//  3. 确定性：同一输入永远得到同一输出。排序使用「置信度 → 优先级 → 规则 ID」
//     三级键，杜绝 map 迭代顺序带来的抖动。
package engine

import (
	"math"
	"runtime"
	"sort"
	"sync"

	"github.com/bannerprint/bannerprint/internal/model"
	"github.com/bannerprint/bannerprint/internal/parsers"
	"github.com/bannerprint/bannerprint/internal/rules"
)

// Engine 持有不可变的规则集与解析器列表，可安全并发调用。
type Engine struct {
	set       *rules.Set
	parsers   []parsers.Parser
	maxBanner int
}

// New 构造引擎。maxBannerBytes <= 0 时使用 8192（与 spec §4.1 一致）；
// enableTLS=false 时移除 TLS 解析器，使 TLS 输入降级为 unknown。
func New(set *rules.Set, maxBannerBytes int, enableTLS bool) *Engine {
	ps := make([]parsers.Parser, 0, 6)
	for _, p := range parsers.All() {
		if p.Protocol() == "TLS" && !enableTLS {
			continue
		}
		ps = append(ps, p)
	}
	if maxBannerBytes <= 0 {
		maxBannerBytes = 8192
	}
	return &Engine{set: set, parsers: ps, maxBanner: maxBannerBytes}
}

// Fingerprint 识别单条输入。
//
// 返回值一定是一个「完整」的 Result：即使内部 panic，也返回 unknown 而非零值，
// 保证 IP/Port 回显与字段完整性不被破坏。
func (e *Engine) Fingerprint(item model.Item) (res model.Result) {
	res = model.Unknown(item.IP, item.Port)
	defer func() {
		if r := recover(); r != nil {
			// 不上抛、不打印到 stdout：单条数据的异常属于可预期噪声，
			// 由上层统计 unknown 数量即可发现问题。
			res = model.Unknown(item.IP, item.Port)
		}
	}()

	banner := item.Banner
	if len(banner) > e.maxBanner {
		banner = banner[:e.maxBanner]
	}

	candidates := make([]model.Candidate, 0, 4)
	for _, p := range e.parsers {
		fields, ok := p.Parse(banner)
		if !ok {
			continue
		}
		candidates = append(candidates, e.set.Match(p.Protocol(), banner, fields)...)
	}
	if len(candidates) == 0 {
		return res
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence
		}
		if a.Priority != b.Priority {
			return a.Priority > b.Priority
		}
		return a.RuleID < b.RuleID
	})

	best := candidates[0]
	if best.Protocol == "" {
		return res
	}
	return model.Result{
		IP:         item.IP,
		Port:       item.Port,
		Protocol:   best.Protocol,
		Product:    best.Product,
		Version:    best.Version,
		OSHint:     best.OSHint,
		Confidence: round2(best.Confidence),
	}
}

// FingerprintBatch 批量识别，结果与输入**下标一一对应**（顺序即契约）。
// workers <= 0 时取 GOMAXPROCS；小批量直接串行，避免 goroutine 调度开销。
func (e *Engine) FingerprintBatch(items []model.Item, workers int) []model.Result {
	results := make([]model.Result, len(items))
	if len(items) == 0 {
		return results
	}
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers > len(items) {
		workers = len(items)
	}
	if workers == 1 {
		for i := range items {
			results[i] = e.Fingerprint(items[i])
		}
		return results
	}

	indexes := make(chan int)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := range indexes {
				results[i] = e.Fingerprint(items[i])
			}
		}()
	}
	for i := range items {
		indexes <- i
	}
	close(indexes)
	wg.Wait()
	return results
}

// round2 四舍五入到两位小数，避免 0.7000000000000001 这类浮点噪声进入 JSON。
func round2(v float64) float64 {
	return math.Round(v*100) / 100
}
