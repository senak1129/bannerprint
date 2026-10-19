package client

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"text/tabwriter"

	"github.com/bannerprint/bannerprint/internal/model"
)

// RenderTable 输出定宽表格 + 末尾统计。
//
// 表头保持 ASCII 大写：中文字符在终端占两列宽，混排会让 tabwriter 算错对齐。
// 空字段显示为 "-"，避免读者误以为这一列缺失。
func RenderTable(w io.Writer, results []model.Result) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "IP\tPORT\tPROTOCOL\tPRODUCT\tVERSION\tOS_HINT\tCONF")
	for _, r := range results {
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\t%.2f\n",
			dash(r.IP), r.Port, orUnknown(r.Protocol),
			dash(r.Product), dash(r.Version), dash(r.OSHint), r.Confidence)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w, Summary(results))
	return err
}

// RenderJSON 输出与 server 响应同构的数组（缩进 2 空格，便于 diff 与人工核对）。
func RenderJSON(w io.Writer, results []model.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(results)
}

// Summary 生成一行统计：总数、unknown 数、各协议计数、平均置信度。
//
// 平均置信度只统计**已识别**条目：把 unknown 的 0.0 计入分母会让
// 「识别质量」被数据脏污程度稀释，读数失去意义。
func Summary(results []model.Result) string {
	counts := map[string]int{}
	var unknown, recognized int
	var sum float64

	for _, r := range results {
		if r.Protocol == model.ProtocolUnknown || r.Protocol == "" {
			unknown++
			continue
		}
		counts[r.Protocol]++
		recognized++
		sum += r.Confidence
	}

	// 按数量降序、同数量按协议名字典序，保证多次运行输出稳定。
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if counts[names[i]] != counts[names[j]] {
			return counts[names[i]] > counts[names[j]]
		}
		return names[i] < names[j]
	})

	avg := 0.0
	if recognized > 0 {
		avg = sum / float64(recognized)
	}
	return fmt.Sprintf("── %d items | %d unknown | %s | avg conf %.2f",
		len(results), unknown, joinCounts(names, counts), avg)
}

func joinCounts(names []string, counts map[string]int) string {
	if len(names) == 0 {
		return "no recognized protocol"
	}
	out := ""
	for i, n := range names {
		if i > 0 {
			out += " · "
		}
		out += fmt.Sprintf("%s %d", n, counts[n])
	}
	return out
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func orUnknown(s string) string {
	if s == "" {
		return model.ProtocolUnknown
	}
	return s
}
