# syntax=docker/dockerfile:1.7
#
# 多阶段构建，两个可独立运行的产物：server / client。
#
# 打包思路：
#   1. 依赖层与源码层分离 —— COPY go.mod go.sum 后立即 go mod download，
#      只要依赖没变，改业务代码不会重新下载模块，二次构建显著变快；
#   2. 静态编译（CGO_ENABLED=0）—— 产物不依赖 libc，最终镜像可以做到 scratch；
#   3. -trimpath 去掉本机绝对路径，-s -w 去符号表，VERSION 走 ldflags 注入，
#      镜像里可以用 `server -version` 追溯是哪次构建；
#   4. 默认 scratch：没有 shell、没有包管理器、没有 curl，攻击面最小；
#      同时因为健康探针由二进制自带（server healthcheck 子命令），不需要 shell。
#      若需要排障，可用 --build-arg BASE_IMAGE=alpine:3.20 换一个带 shell 的底座。
#
# 评估者只需 `docker compose build`，无需本机安装 Go。
ARG GO_VERSION=1.23
ARG BASE_IMAGE=scratch

# ---------- build ----------
FROM golang:${GO_VERSION}-alpine AS build

WORKDIR /src

# 静态链接；-buildvcs=false 避免在没有 .git 的构建上下文里报错。
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOFLAGS=-buildvcs=false

# 依赖单独一层：缓存命中的关键。
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG VERSION=dev

# 两个二进制共用同一套编译参数；--mount=type=cache 让重复构建复用编译缓存。
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/server ./cmd/server && \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/client ./cmd/client

# ---------- test ----------
# 独立 target：`docker build --target test .` 即可在无本机 Go 的环境跑完整测试。
# 不带 -race：竞态检测需要 cgo，而基础镜像默认没有 C 工具链，这里优先保证可运行。
FROM build AS test
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go test ./... -count=1

# ---------- server ----------
FROM ${BASE_IMAGE} AS server

# 仅拷贝二进制；uid/gid 65532 是 distroless 约定的 nonroot，
# 这里直接用它，换底座（alpine）时也保持一致，无需 /etc/passwd。
COPY --from=build --chown=65532:65532 /out/server /app/server

USER 65532:65532
EXPOSE 8080

# exec 形式：server 是 PID 1，能直接收到 SIGTERM 做优雅退出。
ENTRYPOINT ["/app/server"]

# ---------- client ----------
FROM ${BASE_IMAGE} AS client

COPY --from=build --chown=65532:65532 /out/client /app/client

USER 65532:65532

ENTRYPOINT ["/app/client"]
