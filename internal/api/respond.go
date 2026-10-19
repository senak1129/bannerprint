package api

import (
	"encoding/json"
	"net/http"
)

// writeJSON 统一成功响应：显式 UTF-8、关闭 HTML 转义
//（banner 里可能出现 < > &，转义成 \u003c 只会让结果更难读）。
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// apiError 是统一的错误响应体：
//
//	{"error":{"code":"invalid_json","message":"...","request_id":"..."}}
type apiError struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

// writeError 输出错误响应。request_id 与访问日志、响应头一致，便于三方对齐。
func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeJSON(w, status, apiError{Error: errorBody{
		Code:      code,
		Message:   message,
		RequestID: requestID(r),
	}})
}
