# task.md — bannerprint 实施任务拆分

> 依据：`spec.md`（v1.0，已冻结）。本文件只做任务分解，**不含实现代码**。
> 时间基准：`T+0` = 开始编码时刻，`T+30` = 交付截止。预估为 AI 批量生成下的乐观值，已含一次返工余量。

---

## 0. 使用说明

### 0.1 优先级定义（4 级）

| 级别 | 名称 | 判定标准 | 是否可砍 |
|---|---|---|---|
| **P0** | 阻断级 | 缺一项则系统跑不起来或硬性功能验收直接不通过 | 不可砍 |
| **P1** | 评分核心 | 直接对应评估者重点检查的 5 个维度（收敛/健康/镜像/权限/解耦） | 不可砍 |
| **P2** | 工程完备 | 决定「代码能否自证」：测试、README、日志、自检脚本、仓库可达 | 可压缩，不可全删 |
| **P3** | 增量增强 | 提升识别深度与健壮性，超时则整体放弃 | 可砍 |

### 0.2 状态标记

`[ ]` 未开始 · `[~]` 进行中 · `[x]` 完成 · `[!]` 阻塞（需记录原因）

### 0.3 硬约束

1. **T+28 必须执行 `git push`**（推送耗时不可控），未完项写入 README 的 Known Limitations。
2. 任何时刻仓库必须处于「可 clone 且能 `docker compose up`」状态；先推可运行版本，再迭代。
3. 每个 P0/P1 任务完成后立即跑该任务的验收命令，**不攒到最后一起验**。

---

## 1. 任务总览

| ID | 任务 | 优先级 | 预估 | 依赖 | spec 章节 |
|---|---|---|---|---|---|
| P0-1 | 仓库骨架与工具链 | P0 | 1.0 | — | §6 |
| P0-2 | 数据模型与配置装配 | P0 | 1.0 | P0-1 | §5 / §9 |
| P0-3 | `jsonx` 宽松 JSON 解码器 | P0 | 2.0 | P0-2 | §4.4 |
| P0-4 | 规则加载器（schema + 模板 + embed） | P0 | 2.0 | P0-2 | §7.2 |
| P0-5 | Parser：SSH + HTTP | P0 | 1.5 | P0-4 | §7.3.1 / §7.3.2 |
| P0-6 | Parser：MySQL + Redis + FTP | P0 | 1.5 | P0-4 | §7.3.3–7.3.5 |
| P0-7 | Engine 仲裁 + unknown 兜底 | P0 | 1.0 | P0-5, P0-6 | §7.1 / §7.4 / §7.5 |
| P0-8 | 规则文件 `rules/*.yaml`（6 份） | P0 | 2.0 | P0-4 | §7.2 / §7.3 |
| P0-9 | HTTP API：`/fingerprint` + `/health` + 中间件 | P0 | 1.5 | P0-7 | §4.2 / §4.3 |
| P0-10 | server main：healthcheck 子命令 + 优雅退出 | P0 | 1.5 | P0-9 | §4.3 / §10.4 |
| P0-11 | 金标准对齐（20/20 全绿） | P0 | 2.0 | P0-8, P0-10 | §12.3 |
| P1-1 | client CLI | P1 | 1.5 | P0-9 | §8 |
| P1-2 | Dockerfile（多阶段 / 双 target） | P1 | 2.0 | P0-10, P1-1 | §10.1 |
| P1-3 | docker-compose（网络 + 健康 + 权限） | P1 | 1.5 | P1-2 | §11 / §10.2 / §10.3 |
| P1-4 | 端到端联调与故障注入 | P1 | 1.0 | P1-3 | §10.4 / §12.4 |
| P2-1 | 单元 / 契约 / 规则测试 | P2 | 1.5 | P1-4 | §12.1 |
| P2-2 | README（自证材料） | P2 | 1.5 | P1-4 | §12.2 / §16 |
| P2-3 | 结构化日志与可观测性 | P2 | 1.0 | P0-9 | §10.5 |
| P2-4 | `scripts/verify.sh` 五项自检 | P2 | 0.5 | P1-4 | §12.2 |
| P2-5 | GitHub 推送与可达性验证 | P2 | 0.5 | P2-2 | §16 R5 |
| P3-1 | TLS 检测 + 开关 | P3 | 0.5 | P0-8 | §7.3.6 |
| P3-2 | SIGHUP 热加载 + degraded 状态 | P3 | 1.0 | P0-4 | §7.2 / §4.3 |
| P3-3 | Fuzz 目标 | P3 | 0.5 | P0-7 | §10.6 |
| P3-4 | 扩充规则（Tomcat/Caddy/SQL Server…） | P3 | 1.0 | P0-8 | §7.3 |
| P3-5 | `API_TOKEN` 可选鉴权 | P3 | 0.5 | P0-9 | §9 |

**合计**：P0 ≈ 17 min（T+0–17）· P1 ≈ 6 min（T+17–23）· P2 ≈ 5 min（T+23–28）· P3 = 缓冲。

---

## 2. P0 阻断级（T+0 – T+17）

### P0-1 仓库骨架与工具链 `[ ]`
- **目标**：建立可编译、可测试、可提交的最小骨架。
- **产出**：`go.mod`（module `github.com/<user>/bannerprint`，go 1.23）、目录树（§6）、`.gitignore`、`.dockerignore`、`Makefile` 骨架（fmt/vet/test/build/up/demo）、`LICENSE`（可选）。
- **要点**：依赖仅 `gopkg.in/yaml.v3`；先 `go mod tidy` 保证 `go.sum` 存在（Docker 层缓存依赖它）。
- **验收**：`go build ./...` 通过（此时只有空 main）。
- **依赖**：无。

### P0-2 数据模型与配置装配 `[ ]`
- **目标**：`internal/model` 与 `internal/config` 落地，字段顺序即响应顺序。
- **产出**：`Item`（IP/Port/Banner []byte）、`Result`（7 字段，json tag 顺序 = §5）、`Candidate`；`config.Load()` 读取 §9 全部环境变量并给默认值。
- **要点**：`Result` 的 struct 字段声明顺序必须是 `ip, port, protocol, product, version, os_hint, confidence`（决定 JSON 键序）。
- **验收**：`go test ./internal/model ./internal/config`（字段序断言 + 默认值断言）。
- **依赖**：P0-1。

### P0-3 `jsonx` 宽松 JSON 解码器 `[ ]`
- **目标**：消化非标准转义，避免整批 400。**本项目第一风险点**。
- **产出**：`internal/jsonx/decode.go` + `decode_test.go`；`UnmarshalItems([]byte) ([]Item, error)`。
- **要点**：
  - `\xNN` → 单字节（**不是**转成 `\u00NN`，否则 UTF-8 编码会破坏二进制）；
  - 裸控制字符、`\u0000`、`\r\n`、`\t` 均正确解码；
  - 顶层数组与 NDJSON 自动判别；
  - 单引号 / 尾随逗号 → 明确报错。
- **验收**：`go test ./internal/jsonx -race`；用例至少覆盖 `J\x00\x00\x00\n8.0.32\x00` → 长度 12 且 `[4]==0x0A`。
- **依赖**：P0-2。

### P0-4 规则加载器 `[ ]`
- **目标**：把 YAML 变成可执行的匹配器，产品知识彻底移出 Go 代码。
- **产出**：`internal/rules/{schema.go,loader.go,template.go}` + 测试。
- **要点**：
  - `go:embed rules/*.yaml` 内置；`RULES_DIR` 同名文件**整体替换**、新增追加；
  - 启动强校验：version==1、protocol 枚举、id 全局唯一、regex 可编译、confidence ∈ (0,1)；
  - 模板函数白名单仅 4 个：`osFrom` / `trimV` / `default` / `lower`；
  - `source: raw` 按 latin-1 字节→rune 映射后匹配（避免非 UTF-8 失配）。
- **验收**：加载 `rules/` 全量成功；构造坏 YAML（重复 id / 非法正则）应返回错误而非 panic。
- **依赖**：P0-2。

### P0-5 Parser：SSH + HTTP `[ ]`
- **目标**：两个高频协议的结构化字段抽取器。
- **产出**：`internal/parsers/ssh.go`、`http.go`，统一接口 `Parse([]byte) (fields map[string]string, ok bool)`。
- **要点**：
  - SSH：`(?m)^SSH-<proto>-<software>[ comment]`，允许前导噪声；产出 `ssh.software`、`ssh.comment`；
  - HTTP：状态行 + 头部解析（大小写不敏感），产出 `http.status_line`、`http.server`、`http.powered_by`；
  - **Parser 内不出现任何产品名**（只产出语法字段）。
- **验收**：`go test ./internal/parsers -run 'SSH|HTTP'`，含噪声前缀、重复 Server 头、无 Server 头。
- **依赖**：P0-4。

### P0-6 Parser：MySQL + Redis + FTP `[ ]`
- **目标**：补齐剩余三个必识别协议。
- **产出**：`mysql.go`、`redis.go`、`ftp.go`。
- **要点**：
  - MySQL：按字节解析 `[3B len][1B seq][0x0A][NUL 结尾 version]`，payload_len 不符时按偏移 4/5 容错；产出 `mysql.server_version`；
  - Redis：RESP 首字符 + 关键字，产出 `redis.reply`；反例 `-bash:` 不得命中；
  - FTP：`^\d{3}[ -]`，产出 `ftp.code`、`ftp.text`。
- **验收**：`go test ./internal/parsers -run 'MySQL|Redis|FTP'`，含二进制夹具（`testdata/*.bin`）。
- **依赖**：P0-4。

### P0-7 Engine 仲裁与 unknown 兜底 `[ ]`
- **目标**：多候选收敛为唯一结果，且任何输入都不崩。
- **产出**：`internal/engine/{engine.go,resolve.go}`。
- **要点**：
  - 顺序：Normalize（截断 8192B）→ Probe（Parser 按 priority）→ Rule Match → Resolve；
  - 排序：confidence desc → priority desc → 规则文件字典序；
  - 无候选 → `protocol:"unknown"`、其余空、`confidence:0.0`；
  - 每条输入独立 `recover()`，单条 panic 只降级该条。
- **验收**：`Fingerprint` 对空串 / `nil` / 纯二进制返回 unknown 且不 panic；确定性（同输入跑 100 次结果一致）。
- **依赖**：P0-5、P0-6。

### P0-8 规则文件 `rules/*.yaml`（6 份）`[ ]`
- **目标**：用数据表达产品知识，覆盖 §7.3 全部用例。
- **产出**：`ssh.yaml` `http.yaml` `mysql.yaml` `redis.yaml` `ftp.yaml` `tls.yaml`。
- **要点**：
  - HTTP 规则三条：nginx(0.90) / Apache(0.90) / Jetty(0.85) / Microsoft-IIS(0.90) / generic(0.60)；
  - FTP 关键字表：ProFTPD、vsFTPd、Pure-FTPd、FileZilla、Serv-U；
  - Redis 关键字表：NOAUTH、ERR、WRONGTYPE、NOPERM、PONG、OK（分数 0.70 / 0.65）；
  - 所有 product 归一为 §5 规范名。
- **验收**：`go test ./internal/rules -run TestLoadAll`；`grep -riE 'nginx|openssh|proftpd' internal/ --include=*.go` 输出为空。
- **依赖**：P0-4。

### P0-9 HTTP API `[ ]`
- **目标**：两个接口的契约落地，含错误边界。
- **产出**：`internal/api/{router.go,fingerprint.go,health.go,middleware.go}`。
- **要点**：
  - `POST /fingerprint`：200（含全 unknown）/ 400（非法 JSON、空数组）/ 413（超限）/ 405 / 503（未就绪）；
  - 响应 1:1 保序，仅 7 字段；
  - `GET /health`：`status/version/uptime_s/rules/checks`，未就绪 503，< 5ms；
  - 中间件：recover、request-id（ULID）、body limit、结构化访问日志；
  - 路由白名单，其余 404。
- **验收**：`httptest` 跑通 200/400/405/413；`curl /health | jq -e '.checks.engine_ready'` 为 true。
- **依赖**：P0-7。

### P0-10 server main `[ ]`
- **目标**：进程入口具备运维基本素质。
- **产出**：`cmd/server/main.go`。
- **要点**：
  - flag/env 双入口；`-healthcheck` 子命令（`-url`），成功 exit 0 / 失败 exit 1；
  - `http.Server` 超时四件套（Read/Write/Idle/Header）；
  - SIGTERM/SIGINT 优雅退出（`SHUTDOWN_TIMEOUT` 排水）；
  - 启动打印生效配置（脱敏）+ 规则加载统计。
- **验收**：`./server -healthcheck -url http://127.0.0.1:8080/health; echo $?` → 0（服务起着）/ 1（未起）。
- **依赖**：P0-9。

### P0-11 金标准对齐 `[ ]`
- **目标**：20 条自测输入 → §12.3 全绿，这是识别能力的唯一客观证据。
- **产出**：`data/input.json`（题目原始 20 条，合法 JSON 形式）、`data/expected.json`（§12.3 表）、`internal/engine/golden_test.go`。
- **要点**：逐字段比对（含 confidence 两位小数）；不一致时先改规则再改代码，**禁止为过测试硬编码**。
- **验收**：`go test ./internal/engine -run TestGolden -v` 20/20 通过；输出与 §12.3 完全一致。
- **依赖**：P0-8、P0-10。

---

## 3. P1 评分核心（T+17 – T+23）

### P1-1 client CLI `[ ]`
- **目标**：独立程序，读本地 JSON → 调 server → 展示结果。
- **产出**：`cmd/client/main.go`、`internal/client/{run,render}.go`。
- **要点**：
  - 启动先轮询 `/health`（1s × 30 次），覆盖 `docker compose run` 不等依赖的边界；
  - 分片 500、串行发送、指数退避重试 3 次（4xx 不重试）；
  - `-format table|json`；table 末尾统计（总数/unknown/各协议/平均置信度）；
  - stderr 日志、stdout 结果；退出码 0/2/3/4/5（§8.4）。
- **验收**：`go run ./cmd/client -file data/input.json -format json | jq 'length'` → 20；停掉 server 时退出码为 3。
- **依赖**：P0-9。

### P1-2 Dockerfile（多阶段 / 双 target）`[ ]`
- **目标**：体现编译打包理解：小镜像、可缓存、可追溯。
- **产出**：`Dockerfile`（`# syntax=docker/dockerfile:1.7`）、`.dockerignore` 更新、`docker-bake.hcl`（可选）。
- **要点**：
  - build 阶段 `golang:1.23-alpine`，`CGO_ENABLED=0`、`-trimpath`、`-ldflags "-s -w -X main.version=$VERSION"`；
  - `COPY go.mod go.sum` → `go mod download`（`--mount=type=cache`）→ `COPY . .`；
  - 两个 final stage：`AS server` / `AS client`，均基于 `gcr.io/distroless/static-debian12:nonroot`；
  - `ARG BASE_IMAGE` 可切 alpine（应对拉取受限）。
- **验收**：`docker build --target server -t bannerprint/server:dev .` 成功；`docker image ls` 中 server ≤ 12MB；二次构建命中缓存。
- **依赖**：P0-10、P1-1。

### P1-3 docker-compose（网络 + 健康 + 权限）`[ ]`
- **目标**：一键启动，且五维评分点在配置里可见。
- **产出**：`docker-compose.yml`（§11 全文）、`.env.example`。
- **要点**：
  - `internal: true` 网络承载 client↔server；`edge` 仅 server；
  - `SERVER_BIND` 默认 `127.0.0.1`，端口仅发布 server；
  - healthcheck 用 `/app/server healthcheck`，`start_period: 5s`；
  - client：`profiles: [client]`、`condition: service_healthy`、**禁止 restart**；
  - 硬化：`read_only`、`cap_drop: [ALL]`、`no-new-privileges`、`user 65532`、`tmpfs /tmp`、mem/cpus/pids 限制；
  - `./rules` 只读挂载。
- **验收**：`docker compose config -q` 通过；`docker compose up -d --build --wait` 90s 内 healthy。
- **依赖**：P1-2。

### P1-4 端到端联调与故障注入 `[ ]`
- **目标**：证明「一键启动 + 真实启动依赖」不是纸面承诺。
- **产出**：无新代码，产出验证记录（写入 README 的 Verification 段）。
- **要点**：
  - `up --wait` → `curl /fingerprint` → `run client` 全链路；结果与 `data/expected.json` 一致；
  - 停 server 后 `docker compose run client` 应快速失败（非挂死）；
  - 容器内 `/bin/sh` 不存在、`touch /x` 失败；
  - `docker network inspect bannerprint_internal` → `Internal: true`。
- **验收**：上述 4 条全部通过并留命令输出。
- **依赖**：P1-3。

---

## 4. P2 工程完备（T+23 – T+28）

### P2-1 单元 / 契约 / 规则测试 `[ ]`
- **目标**：`go test ./... -race` 全绿，且测试本身是规格的可执行副本。
- **产出**：各包 `_test.go`、`internal/api/api_test.go`（httptest）、`testdata/`。
- **要点**：parser 表驱动（含二进制/超长/非 UTF-8/噪声）；规则全量加载；契约 200/400/405/413/503；golden 测试。
- **验收**：`make test`（容器内跑，无需本机 Go）通过。
- **依赖**：P1-4。

### P2-2 README（自证材料）`[ ]`
- **目标**：评估者不看代码也能复现结论；代码能自证。
- **产出**：`README.md`。
- **要点**（按此顺序）：
  1. 一句话定位 + 30 秒快速开始（3 条命令）；
  2. 接口契约 + 真实 curl/输出示例；
  3. 架构图（client/server/rules）+ 目录说明；
  4. **设计决策**：为什么规则与代码分离、为什么端口不当硬判据、为什么自研 jsonx、为什么 distroless + 子命令探针；
  5. 规则扩展指南（新增一个产品的 3 步）；
  6. 验证清单（§12.2 五项 + 命令）；
  7. Known Limitations。
- **验收**：新机器仅用 README 能跑通；无「待补充」占位。
- **依赖**：P1-4。

### P2-3 结构化日志与可观测性 `[ ]`
- **目标**：排障可用，且不泄露扫描数据。
- **产出**：`internal/obs/logger.go`。
- **要点**：JSON 行日志（ts/level/msg/request_id/route/status/items/unknown/duration_ms）；debug 打 `rule_id` + banner 前 64B（NUL 转义）；info 不打完整 banner。
- **验收**：`LOG_LEVEL=debug` 时能看到 rule_id；`docker compose logs server | jq .` 每行可解析。
- **依赖**：P0-9。

### P2-4 `scripts/verify.sh` 五项自检 `[ ]`
- **目标**：把「评估重点」变成一条命令可复现的证据。
- **产出**：`scripts/verify.sh` + `make verify`。
- **要点**：依次检查 网络收敛 / 健康态 / 镜像体积与层 / 非 root+只读 / `grep` 无产品名，逐项打印 PASS/FAIL。
- **验收**：`make verify` 输出 5×PASS。
- **依赖**：P1-4。

### P2-5 GitHub 推送与可达性验证 `[ ]`
- **目标**：满足「评估者可离线 clone」的硬性交付条件。
- **产出**：远端仓库 + 首个 commit + tag `v1.0`。
- **要点**：`git init` → commit（信息按模块分段）→ `gh repo create --public` → push；**T+28 前执行**；push 后 `git clone` 到临时目录验证。
- **验收**：`git clone <url> /tmp/x && cd /tmp/x && docker compose up -d --build --wait` 成功。
- **依赖**：P2-2。

---

## 5. P3 增量增强（仅在 T+26 前完成 P2 后）

| ID | 任务 | 触发条件 | 验收 |
|---|---|---|---|
| P3-1 | TLS record 检测 + `ENABLE_TLS_DETECT` 开关 | P0-11 全绿且有余量 | `\x16\x03\x01...` → `TLS/0.60`；关闭则 unknown |
| P3-2 | SIGHUP 热加载 + `/health` degraded | 同上 | 改 YAML → `kill -HUP` → 新结果生效，无需重启 |
| P3-3 | `FuzzFingerprint` | 同上 | `go test -fuzz=. -fuzztime=60s` 无崩溃 |
| P3-4 | 扩充规则（Tomcat/Caddy/lighttpd/SQL Server/Postgres） | 同上 | 新增规则不改一行 Go 代码 |
| P3-5 | `API_TOKEN` 可选鉴权 | 同上 | 设置后无 Bearer 返回 401，未设置时行为不变 |

> P3 一律**在独立分支/独立 commit** 上做，确保主分支始终处于可交付状态。

---

## 6. 关键路径与时间盒

```
T+0   P0-1 ─ P0-2 ─┬─ P0-3 ──────────────┐
                    ├─ P0-4 ─┬─ P0-5 ─┐   │
                    │        ├─ P0-6 ─┼─ P0-7 ─ P0-9 ─ P0-10 ─┐
                    │        └─ P0-8 ─┴────────────── P0-11 ◀─┘
T+17  P1-1 ─ P1-2 ─ P1-3 ─ P1-4
T+23  P2-1 / P2-2 / P2-3 / P2-4（可并行）─ P2-5
T+28  git push（硬点）
T+30  截止
```

| 阶段 | 起止 | 出口条件 |
|---|---|---|
| A 骨架与解析 | T+0–4 | `go build` 通过，`jsonx` 单测绿 |
| B 识别引擎 | T+4–12 | 20 条自测全绿 |
| C 服务与客户端 | T+12–17 | `curl` 两接口正常，client 跑通 |
| D 容器化 | T+17–23 | `up --wait` healthy + client 联调通过 |
| E 自证与交付 | T+23–28 | 测试绿、README 齐、仓库可 clone |

---

## 7. 超时降级顺序（从先砍到后砍）

1. **P3 全部**（最先放弃，不影响任何硬性验收）
2. P2-4 `verify.sh`（README 里手写命令替代）
3. P2-3 日志细化（保留基本访问日志）
4. P2-1 中的 fuzz 与部分边界单测（**保留** golden + 契约测试）
5. P3-2 热加载（改为重启生效，README 说明）

**绝不砍**：P0 全部 · P1-1/2/3 · P2-2 的「快速开始 + 接口 + 设计决策」三节 · P2-5。

---

## 8. 完成定义（DoD）

一条 `docker compose up -d --build --wait` 之后，同时满足：

- [ ] 90s 内 server 进入 `healthy`；`/health` 返回 `engine_ready: true`
- [ ] `POST /fingerprint` 对 20 条自测输入返回 200，结果与 `data/expected.json` 逐字段一致（20/20）
- [ ] 未识别输入（`QUIT\r\n`）返回 `protocol:"unknown"`，进程不退出，`/health` 仍 ok
- [ ] `docker compose run --rm client -file /data/input.json` 打印完整表格与统计
- [ ] `grep -riE 'nginx|openssh|proftpd' internal/ --include=*.go` 无输出
- [ ] 容器以 uid 65532 运行、根文件系统只读、`cap_drop: ALL`
- [ ] `go test ./... -race` 通过
- [ ] `git clone <repo>` 到空目录后可直接 `docker compose up`
- [ ] README 含快速开始、接口示例、设计决策、规则扩展、Known Limitations

---

## 9. 任务看板（执行时勾选）

```
P0  [ ]P0-1 [ ]P0-2 [ ]P0-3 [ ]P0-4 [ ]P0-5 [ ]P0-6 [ ]P0-7 [ ]P0-8 [ ]P0-9 [ ]P0-10 [ ]P0-11
P1  [ ]P1-1 [ ]P1-2 [ ]P1-3 [ ]P1-4
P2  [ ]P2-1 [ ]P2-2 [ ]P2-3 [ ]P2-4 [ ]P2-5
P3  [ ]P3-1 [ ]P3-2 [ ]P3-3 [ ]P3-4 [ ]P3-5
```
