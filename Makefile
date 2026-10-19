# bannerprint 常用命令。所有目标都不依赖本机 Go 之外的私有工具链。
VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: help fmt vet test test-race build up down logs demo verify clean

help: ## 列出所有可用目标
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

fmt: ## gofmt 检查（不改文件）
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || (echo "需要 gofmt 以上文件" && exit 1)

vet: ## go vet 静态检查
	go vet ./...

test: ## 单元测试（本机 Go）
	go test ./... -count=1

test-race: ## 单元测试 + 竞态检测（需 cgo）
	CGO_ENABLED=1 go test ./... -race -count=1

build: ## 本机编译两个二进制到 bin/
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/server ./cmd/server
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/client ./cmd/client

up: ## 构建并启动服务端，等待 healthy
	docker compose up -d --build --wait

down: ## 停止并清理（含网络）
	docker compose down -v --remove-orphans

logs: ## 跟踪 server 日志
	docker compose logs -f server

demo: ## 一键演示：起服务 + 跑 client + 打印表格
	docker compose up -d --build --wait
	docker compose run --rm client -file /data/input.json

verify: ## 五项生产级自检（见 scripts/verify.sh）
	./scripts/verify.sh

clean: ## 清理本机产物
	rm -rf bin
