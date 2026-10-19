// Package rulesdata 只做一件事：把规则 YAML 编译进二进制。
//
// 为什么单独成包：go:embed 只能嵌入**当前包目录下**的文件，而规则需要以
// 普通目录（./rules）的形式存在于仓库根，供 compose 只读挂载覆盖。
// 因此在此放一个仅含 embed 声明的包，让 internal/rules 通过 import 使用。
//
// 注意：本目录同时被 Dockerfile COPY 进镜像（/app/rules）作为内置兜底；
// 运行时挂载 /etc/bannerprint/rules.d 时以挂载内容为准。
package rulesdata

import "embed"

// FS 内嵌仓库根 rules/ 目录下的全部 YAML 规则文件。
//
//go:embed *.yaml
var FS embed.FS
