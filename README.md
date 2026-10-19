# bannerprint

> 批量 Banner 指纹识别：吃进 `(ip, port, banner)`，吐出 `protocol / product / version / os_hint / confidence`。
> Go + client/server 架构，`docker compose up` 一键启动，识别规则以 YAML 外置、与代码彻底解耦。

---

## 1. 快速开始（3 条命令）

```bash
git clone <repo-url> bannerprint && cd bannerprint
docker compose up -d --build --wait          # 构建并等待 healthy
docker compose run --rm client -file /data/input.json
```

预期输出（`data/input.json` 为题目给的 20 条自测数据）：

```
IP        PORT   PROTOCOL  PRODUCT        VERSION  OS_HINT  CONF
1.2.3.4   22     SSH       OpenSSH        8.9p1    Ubuntu   0.95
1.2.3.5   80     HTTP      nginx          1.24.0   -        0.90
1.2.3.6   443    HTTP      Apache         2.4.57   -        0.90
1.2.3.7   3306   MySQL     MySQL          8.0.32   -        0.90
1.2.3.8   6379   Redis     Redis          -        -        0.70
1.2.3.9   21     FTP       ProFTPD        1.3.7    -        0.90
1.2.3.10  8080   HTTP      Jetty          9.4.51   -        0.85
...
1.2.3.23  12345  unknown   -              -        -        0.00
── 20 items | 1 unknown | HTTP 7 · FTP 3 · Redis 3 · SSH 3 · MySQL 2 · TLS 1 | avg conf 0.85
```

其他常用命令：

```bash
docker compose run --rm client -file /data/input.json -format json   # JSON 输出，可管道给 jq
docker compose logs -f server                                        # 结构化日志
docker compose down -v                                               # 关停并清网络
```

> Windows / Git Bash 用户注意：MSYS 会把 `/data/input.json` 自动改写成 Windows 路径，
> 需要临时关闭路径转换：`MSYS_NO_PATHCONV=1 docker compose run --rm client -file /data/input.json`。
> PowerShell、cmd、Linux、macOS 无此问题。

本机不开容器也能跑（需 Go 1.23+）：

```bash
make build && ./bin/server &                # 服务端
./bin/client -file data/input.json          # 客户端
```

---

## 2. 接口契约

### 2.1 `POST /fingerprint`

请求体是数组（也接受 NDJSON，每行一个对象）：

```json
[
  {"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
  {"ip":"1.2.3.7","port":3306,"banner":"J\u0000\u0000\u0000\n8.0.32\u0000"}
]
```

响应 `200`，与输入 **1:1 同序**，每项恰好 7 个字段：

```json
[
  {"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"Ubuntu","confidence":0.95},
  {"ip":"1.2.3.7","port":3306,"protocol":"MySQL","product":"MySQL","version":"8.0.32","os_hint":"","confidence":0.90}
]
```

错误分层是本服务最重要的契约：

| 情形 | 状态码 | 说明 |
|---|---|---|
| 某条数据认不出来 | **200** + `protocol:"unknown"` | 不是错误，绝不因为脏数据整批失败 |
| 非 JSON / 空数组 | 400 | `{"error":{"code":"invalid_json",...}}` |
| 超过 `MAX_BODY_BYTES` / 条数上限 | 413 | |
| 方法不对 | 405 | 带 `Allow` 头 |
| 规则未加载完 | 503 | 实际不会出现：加载失败进程直接退出 |

```bash
curl -s http://127.0.0.1:8080/fingerprint -H 'Content-Type: application/json' \
  -d '[{"ip":"1.2.3.23","port":12345,"banner":"QUIT\r\n"}]'
# [{"ip":"1.2.3.23","port":12345,"protocol":"unknown","product":"","version":"","os_hint":"","confidence":0}]
```

### 2.2 `GET /health`

```json
{
  "status": "ok",
  "version": "dev",
  "uptime_s": 12,
  "rules": {"loaded": 24, "files": 6, "errors": 0, "loaded_at": "2026-10-19T08:00:00Z"},
  "checks": {"rules_loaded": true, "engine_ready": true}
}
```

`checks.engine_ready` 才是编排层要看的信号：进程活着但规则为空，返回 `503`。

### 2.3 非标准转义

题目给的 MySQL banner 是 `"J\x00\x00\x00\n8.0.32\x00"` —— `\xNN` **不是合法 JSON 转义**，
`encoding/json` 会直接报语法错误，导致「一条脏数据 → 整批 400」。

因此本项目自带 `internal/jsonx`：逐字节扫描字符串 token，额外接受 `\xNN`（解码为单字节，
而不是 `\u00NN`，否则 UTF-8 编码会把 `0xA5` 变成两个字节、破坏 TLS/MySQL 二进制特征）、
裸控制字符与 UTF-16 代理对；仍然拒绝单引号、尾随逗号等歧义写法。**client 与 server 共用这一实现**，
不会出现「本地能读、服务端 400」的割裂。

---

## 3. 架构

```
            ┌──────────────┐   /data/input.json (ro)
            │    client    │◀──────── 宿主目录挂载
            │  (一次性)     │
            └──────┬───────┘
                   │ HTTP（仅 internal 网络，服务名 DNS）
            ┌──────▼───────────────────────────────┐
            │              server                  │
            │  api → engine → parsers → rules      │
            │         ▲                            │
            │         └── rules/*.yaml (ro 挂载)    │
            └──────┬───────────────────────────────┘
                   │ 127.0.0.1:8080（只发布回环）
                宿主机
```

| 目录 | 职责 |
|---|---|
| `cmd/server` | 进程入口：healthcheck 子命令、超时四件套、优雅退出 |
| `cmd/client` | 独立 CLI：读文件 → 调用 → 表格/JSON 渲染 |
| `internal/api` | 路由、限额、错误映射、request-id、访问日志 |
| `internal/engine` | 归一化 → 探针 → 规则匹配 → 仲裁；unknown 兜底 |
| `internal/parsers` | **协议语法**：SSH 标识串、HTTP 头、MySQL 握手包、RESP、FTP 应答码、TLS record |
| `internal/rules` | **产品知识**的加载与执行（YAML → 编译后的匹配器） |
| `rules/*.yaml` | 全部产品知识（nginx/Apache/OpenSSH…），可只读挂载覆盖 |
| `data/` | 自测输入与金标准输出 |

**分层的关键**：`internal/parsers` 里不出现任何产品名，只产出语法字段（`ssh.software`、`http.server`）；
`rules/*.yaml` 负责把语法字段翻译成产品与版本。自检命令：

```bash
grep -riE 'nginx|openssh|apache|proftpd|redis' internal/ --include=*.go   # 必须为空
```

---

## 4. 设计决策（为什么这样做）

**① 规则与代码分离**
Parser 回答「这串字节是不是 SSH」，规则回答「`OpenSSH_8.9p1` 拆成产品 `OpenSSH` + 版本 `8.9p1`」。
前者稳定且少量，写进代码；后者会持续新增（每出一个中间件就要加一条），用 YAML 表达。
结果是新增产品**不需要改一行 Go**、不需要重新编译镜像 —— 只读挂载的 `./rules` 改了即生效（重启容器）。

**② 端口不作为协议判据**
验收数据里 8443 跑 nginx、8888 跑 IIS 都很正常。端口只用于**同分候选的排序**，
且**不加置信度**，否则示例里 `nginx:80 = 0.90` 会被悄悄加成 0.92，与金标准对不上。

**③ 自研宽松 JSON 解码器**
见 §2.3。这是本项目的第一风险点：解码器一挂，识别能力再强也是整批 400。

**④ scratch 镜像 + 二进制自带探针**
`CGO_ENABLED=0` 静态编译后，最终镜像只需要一个二进制，因此可以用 `scratch`：
没有 shell、没有包管理器、没有 `curl`。代价是普通 `CMD curl -f localhost/health` 式探针不可用，
于是 server 内置 `healthcheck` 子命令，并且校验的是 `engine_ready` 而不是「端口能连上」——
容器起来了但规则没加载的中间态，不该被编排层当成可用实例。
需要排障时可 `--build-arg BASE_IMAGE=alpine:3.20` 换一个带 shell 的底座。

**⑤ 一次性客户端不使用 restart**
`client` 在 compose 里用 `profiles: ["client"]` 且显式 `restart: "no"`。
一次性任务容器若带 `unless-stopped`，退出后会被反复拉起；`docker compose up` 也会因为它退出而显示异常。
同时 `depends_on.condition: service_healthy` 之外，客户端自己还会轮询 `/health`（1s × 30）——
因为 `docker compose run` 并不总是等待依赖健康，这一层自旋是「启动依赖真实生效」的第二道保险。

---

## 5. 新增一个产品：3 步

以新增 `Caddy` 为例（假设 Parser 已产出 `http.server` 字段，HTTP Parser 已覆盖）：

```yaml
# rules/http.yaml 里追加
  - id: http.caddy
    priority: 100
    match:
      source: field
      field: http.server
      regex: '^Caddy/(?P<version>\S+)'
    fields:
      product: 'Caddy'
      version: '{{ .version }}'
      os_hint: ''
    confidence:
      base: 0.90
```

1. 写规则（如上）；
2. `docker compose restart server`（规则在启动时加载并强校验）；
3. `docker compose run --rm client -file /data/input.json` 验证。

规则加载期会强校验：`version==1`、协议在枚举内、`id` 全局唯一、正则可编译、`confidence ∈ (0,1)`。
任一不合法 → 启动失败并打印具体文件与规则 ID（fail fast，绝不带着半套规则服务）。

规则可用字段：

| 键 | 含义 |
|---|---|
| `match.source` | `raw`（原始 banner，按 latin-1 映射）或 `field`（Parser 产出字段） |
| `match.field` | `source: field` 时必填，如 `http.server`、`ssh.software` |
| `match.regex` | RE2 语法，支持命名捕获组 |
| `fields.product/version/os_hint` | Go template，可用捕获组与 `osFrom`/`trimV`/`default`/`lower` |
| `confidence.base` | 基准分，`version` 捕获组为空时自动 −0.10 |

---

## 6. 验证清单

```bash
make verify          # 五项自检，逐项打印 PASS/FAIL
```

| # | 检查项 | 命令 | 期望 |
|---|---|---|---|
| 1 | 容器间访问收敛 | `docker network inspect bannerprint_internal -f '{{.Internal}}'` | `true`；client 无端口发布 |
| 2 | 健康检测真实 | `curl -s 127.0.0.1:8080/health \| jq .checks` | 两项均 `true` |
| 3 | 镜像与分层 | `docker image ls bannerprint/server` | 静态二进制，scratch 底座，≤ 12MB |
| 4 | 权限收紧 | `docker inspect -f '{{.Config.User}} {{.HostConfig.ReadonlyRootfs}}' <c>` | `65532:65532 true` |
| 5 | 规则与代码解耦 | `grep -riE 'nginx\|openssh' internal/ --include=*.go` | 无输出 |

故障注入（证明「启动依赖」不是纸面承诺）：

```bash
docker compose stop server
docker compose run --rm client -file /data/input.json   # 30s 内以退出码 3 失败，而不是挂死
docker compose start server
```

客户端退出码：`0` 成功 · `2` 参数/输入错误 · `3` 连不上 server · `4` 服务端错误 · `5` 写盘失败。

---

## 7. 配置项

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `SERVER_ADDR` | `:8080` | 监听地址 |
| `RULES_DIR` | `/etc/bannerprint/rules.d` | 外部规则目录，同名文件整体替换内置规则 |
| `MAX_BODY_BYTES` | `33554432` | 请求体上限 |
| `MAX_BATCH_ITEMS` | `10000` | 单批条数上限 |
| `MAX_BANNER_BYTES` | `8192` | 单条 banner 截断阈值 |
| `LOG_LEVEL` / `LOG_FORMAT` | `info` / `json` | 日志级别与格式 |
| `ENABLE_TLS_DETECT` | `true` | TLS record 识别开关 |
| `SHUTDOWN_TIMEOUT` | `10s` | 优雅退出排水时间 |
| `SERVER_URL` | `http://127.0.0.1:8080` | 客户端专用 |
| `VERSION` / `SERVER_PORT` | `dev` / `8080` | compose 用 |

---

## 8. 已知边界

- **只做被动指纹**：不主动发包探测，识别能力受 banner 信息量限制；`banner` 为空一律 `unknown`。
- **版本号不做语义化归一**：`1.24.0` 与 `1.24` 原样保留，不猜测补丁号。
- **置信度是启发式**：规则基准分 + 缺失惩罚，用于排序与人工筛检，不构成概率保证。
- **规则热加载未实现**：修改 `rules/` 后需 `docker compose restart server`（约 1s）。
- **TLS 仅识别 record 层**：能从 `\x16\x03\x01` 判断是 TLS，但不解析证书里的产品信息。
- **不支持 IPv6 字面量校验**：`ip` 字段原样回显，不做合法性校验（避免脏数据导致整批失败）。
