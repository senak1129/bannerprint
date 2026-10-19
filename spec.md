# Banner 指纹识别系统 — 技术规格说明书（spec.md）

| 项 | 内容 |
|---|---|
| 项目代号 | `bannerprint` |
| 文档版本 | v1.0 |
| 状态 | 已冻结（实现以本文为准） |
| 语言 / 运行时 | Go 1.23（CGO 关闭，静态编译） |
| 交付形态 | `docker compose up` 一键启动的源码仓库（server + client + rules + tests） |
| 交付时限 | 30 分钟（含编码、自测、README、推送 GitHub） |

---

## 1. 目标与非目标

### 1.1 目标

1. 接收一批「网络扫描原始数据」`(ip, port, banner)`，输出识别结果：`protocol / product / version / os_hint / confidence`。
2. 双进程架构：`server`（HTTP 服务，无状态、纯计算）+ `client`（独立 CLI，读本地 JSON 文件、调用 server、展示结果）。
3. 服务端契约：`POST /fingerprint`（批量识别）、`GET /health`（健康检查）。
4. 识别能力下限：SSH、HTTP（nginx / Apache / Jetty）、MySQL、Redis、FTP 必须准确；
   任何无法识别的输入必须降级为 `protocol: "unknown"`，**不得返回 5xx、不得 panic、不得中断整批处理**。
5. 以「生产级部署」标准交付：容器间访问收敛、真实健康检测驱动的启动依赖、多阶段构建、容器权限收紧、**识别规则与程序代码解耦**。

### 1.2 非目标（明确不做，避免范围蔓延）

| 不做 | 原因 |
|---|---|
| 主动扫描 / 端口探测 | 输入是已采集的 banner，server 不做任何出网请求（保证可离线、可复现、无 SSRF 面） |
| 数据库持久化 | 无状态批处理，结果由 client 落盘；引入 DB 只会增加启动依赖与故障点 |
| 认证 / 计费 / 多租户 | 内网服务；如需暴露可开启可选 `API_TOKEN`（默认关闭，保证评估者可直接 curl） |
| TLS 终止 | 属于边缘代理职责；容器内明文 HTTP，仅在 compose 网络内可达 |
| 版本 → CVE 映射 | 超出题目范围，留作规则文件扩展点 |

---

## 2. 术语

| 术语 | 含义 |
|---|---|
| Banner | 目标服务在建立连接后返回的原始字节（可能是文本、HTTP 响应头、二进制握手包） |
| Parser | 协议**语法**解析器（代码），负责判断「这像哪个协议」并抽出结构化字段 |
| Rule | 产品**知识**规则（YAML），负责把字段映射为 `product / version / os_hint / confidence` |
| Candidate | 单条输入经某个 Parser + Rule 得到的候选识别结果 |
| unknown | 无任何 Rule 命中时的兜底结果，置信度 0.00 |

---

## 3. 系统架构

```
┌──────────────────────────────┐        HTTP/1.1 (JSON)        ┌────────────────────────────────┐
│ client (一次性 CLI 容器)      │  POST /fingerprint  ────────▶ │ server (常驻容器)               │
│  - 读 /data/input.json        │  GET  /health       ────────▶ │  net/http + 中间件              │
│  - 分片(500/批) + 重试        │ ◀──────── 200 JSON array ──── │   ├─ api     路由/校验/限流      │
│  - 表格/JSON 展示 + 落盘      │                               │   ├─ engine  归一化→Parser→Rule │
└──────────────────────────────┘                               │   ├─ parsers SSH/HTTP/MySQL/... │
         │ 仅 internal 网络                                      │   └─ rules   YAML（embed+挂载） │
         └───────────────────────────────────────────────────▶ └────────────────────────────────┘
                                                                          │ 只读挂载 ./rules
                                                                          ▼
                                                                  /etc/bannerprint/rules.d
```

设计要点：

- **无状态、纯函数式识别**：`engine.Fingerprint(ctx, Item) model.Result` 不依赖时间、网络、全局可变状态，便于表驱动测试与 fuzz。
- **两层解耦**：
  - Parser（代码）= 协议语法，稳定、少量、可单测；
  - Rule（YAML）= 厂商/产品/版本知识，易增删，评估者可直接改规则验证热加载。
  - Go 代码中**不得出现** `nginx`、`OpenSSH`、`ProFTPD` 等产品名字面量（允许出现在 `rules/*.yaml` 与测试夹具中）。
- **启动即校验**：规则加载失败 → 进程退出（fail fast），`/health` 永远反映「规则已就绪」这一真实状态。
- **故障隔离**：每条输入在独立 `recover()` 边界内处理，单条 panic 只影响该条（降级 unknown），整批继续。

---

## 4. 接口契约

### 4.1 通用约定

| 项 | 约定 |
|---|---|
| Base URL | 容器内 `http://server:8080`；宿主机 `http://127.0.0.1:8080` |
| 编码 | `application/json; charset=utf-8` |
| 请求头 | 可选 `X-Request-ID`（缺省由服务端生成 ULID），响应回显 |
| 超时 | 读 10s / 写 30s / 空闲 60s；单请求处理上限 25s |
| 体积 | 请求体 ≤ 32 MiB；单批 ≤ 10000 条；单条 banner ≤ 8192 字节（超出截断并计数，不报错） |
| 路由白名单 | 仅 `/fingerprint`、`/health`；其余 404（不暴露 pprof/metrics，减小攻击面） |

### 4.2 `POST /fingerprint`

**请求体**：JSON 数组（也接受 NDJSON，逐行一个对象，二者自动判别）。

```json
[
  {"ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
  {"ip": "1.2.3.7", "port": 3306, "banner": "J\u0000\u0000\u0000\n8.0.32\u0000"}
]
```

字段规范：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `ip` | string | 是 | 原样回显，不校验合法性（避免因脏数据整批失败） |
| `port` | int | 是 | 0–65535，仅作弱先验（见 §7.4），不参与硬判定 |
| `banner` | string | 是 | 原始 banner；解码后按字节处理（允许含 NUL / 非 UTF-8） |

**响应体**：JSON 数组，**与输入严格 1:1、顺序一致**（不去重、不排序、不合并）。

```json
[
  {"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"Ubuntu","confidence":0.95},
  {"ip":"1.2.3.7","port":3306,"protocol":"MySQL","product":"MySQL","version":"8.0.32","os_hint":"","confidence":0.9}
]
```

- **默认**响应固定 7 个字段、顺序固定（Go struct 声明顺序），不输出额外字段，避免严格比对型评估器误判。
- 调试信息（命中的 rule id、证据片段）只进日志；仅当显式传 `?explain=1` 时，每条结果额外附带 `_explain` 字段（默认关闭，验收不使用）。
- `confidence` 四舍五入到 2 位小数，范围 `[0.00, 0.99]`；JSON 数字不补零（`0.90` 序列化为 `0.9`，与示例响应一致）。

**状态码**

| 码 | 场景 | 响应体 |
|---|---|---|
| 200 | 正常处理（含全部 unknown、含单条字段缺失降级） | 结果数组 |
| 400 | 非法 JSON / 顶层非数组 / 空数组 / `Content-Type` 非 JSON 且无法解析 | `{"error":{"code":"invalid_json","message":"...","request_id":"..."}}` |
| 401 | 启用 `API_TOKEN` 且 token 不匹配 | 同上，`code=unauthorized` |
| 404 | 未知路由 | 同上，`code=not_found` |
| 405 | 方法不匹配 | 同上，`code=method_not_allowed` |
| 413 | 体积/条数超限 | 同上，`code=payload_too_large` |
| 503 | 规则未就绪（启动中/重载失败） | 同上，`code=not_ready` |
| 500 | 兜底（理论上不应发生，中间件 recover 后返回） | 同上，`code=internal` |

> 关键约定：**「认不出来」永远不是错误**。unknown 走 200。

**示例**

```bash
curl -sS -X POST http://127.0.0.1:8080/fingerprint \
  -H 'Content-Type: application/json' \
  --data-binary @data/input.json | jq .
```

### 4.3 `GET /health`

用途：容器编排的真实健康探针（**不是**静态 `return 200`）。

```json
{
  "status": "ok",
  "version": "dev",
  "uptime_s": 12,
  "rules": {"loaded": 18, "files": 6, "errors": 0, "loaded_at": "2026-10-19T07:58:00Z"},
  "checks": {"rules_loaded": true, "engine_ready": true}
}
```

| 状态 | 条件 | HTTP |
|---|---|---|
| ok | 规则 ≥ 1 条且引擎已构建 | 200 |
| degraded | 规则热加载失败但旧规则仍可用 | 200（`status=degraded`，`errors>0`） |
| not_ready | 启动中 / 无规则 | 503 |

`/health` 必须 < 5ms 返回（纯内存状态读取），避免探针拖慢启动。

### 4.4 输入解析容错（重要）

真实扫描器产出的 JSON 常带非标准转义。解析器必须同时支持：

| 形态 | 处理 |
|---|---|
| `"a\r\nb"`（标准 JSON 转义） | 解码为 CRLF |
| `"J\x00\x00\x00\n8.0.32\x00"`（**非法** `\xNN`） | 自定义 `jsonx` 宽松解码器：`\xNN` 视为单个原始字节 |
| 裸控制字符（`0x00`–`0x1F` 直接出现在字符串内） | 容错接受 |
| 单引号 / 尾随逗号 | **不支持**（明确报 400，避免歧义） |

实现：`internal/jsonx` 提供 `UnmarshalItems([]byte) ([]Item, error)`，逐字节扫描字符串 token，手写转义处理，输出 `[]byte` banner。`encoding/json` 仅用于响应序列化。

**确定性要求**：同一输入必须永远得到同一输出（无 map 迭代顺序依赖、无随机置信度）。

---

## 5. 数据模型

```go
// internal/model
type Item struct {
    IP     string `json:"ip"`
    Port   int    `json:"port"`
    Banner []byte `json:"-"` // 解码后的原始字节
}

type Result struct {
    IP         string  `json:"ip"`
    Port       int     `json:"port"`
    Protocol   string  `json:"protocol"`
    Product    string  `json:"product"`
    Version    string  `json:"version"`
    OSHint     string  `json:"os_hint"`
    Confidence float64 `json:"confidence"`
}
```

**取值规范**

| 字段 | 规范 |
|---|---|
| `protocol` | 规范枚举：`SSH` `HTTP` `MySQL` `Redis` `FTP` `TLS` `unknown`（大小写严格一致） |
| `product` | 厂商原始写法归一：`OpenSSH` `nginx` `Apache` `Jetty` `MySQL` `Redis` `ProFTPD` `vsFTPd` `Pure-FTPd` `Microsoft-IIS`；未知为 `""` |
| `version` | 原样版本串：保留 `p1` 后缀（`8.9p1`）、保留 4 段（`1.24.0`）；**禁止推断/补全**；未知为 `""` |
| `os_hint` | 仅从 banner 中**显式** token 提取（`Ubuntu` `Debian` `CentOS` `Red Hat` `Alpine` `FreeBSD` `Windows`）；不从产品名反推（如 IIS 不自动填 `Windows`）；未知为 `""` |
| `confidence` | 见 §7.5；unknown 固定 `0.00` |

**归一化规则**

1. 版本去 `v` 前缀（`v1.24.0` → `1.24.0`）；保留 `-rc1` / `p1` 等原始修饰。
2. 多个候选 `Server` 头时取第一个；重复 `Server` 头拼接后取首个产品 token。
3. 产品名大小写以映射表为准（`apache` → `Apache`，`nginx` 保持小写）。

---

## 6. 项目结构

```
bannerprint/
├── cmd/
│   ├── server/main.go          # flag/env 解析、路由装配、优雅退出、healthcheck 子命令
│   └── client/main.go          # CLI
├── internal/
│   ├── api/                    # handler、中间件（recover/requestid/limit/log）
│   ├── engine/                 # 归一化 → 候选 → 仲裁
│   ├── parsers/                # ssh.go http.go mysql.go redis.go ftp.go tls.go
│   ├── rules/                  # loader、schema 校验、热加载、go:embed 默认规则
│   ├── jsonx/                  # 宽松 JSON 解码
│   ├── model/                  # Item / Result / Candidate
│   └── config/                 # 环境变量装配
├── rules/
│   ├── ssh.yaml  http.yaml  mysql.yaml  redis.yaml  ftp.yaml  tls.yaml
├── data/
│   ├── input.json              # 题目给的 20 条自测输入
│   └── expected.json           # 自测金标准（见 §12.3）
├── testdata/                   # 单测夹具（含二进制 banner）
├── Dockerfile                  # 多阶段，双 final target：server / client
├── docker-compose.yml
├── Makefile
├── go.mod / go.sum
├── README.md                   # 部署、接口、规则扩展、设计决策
└── spec.md
```

---

## 7. 识别引擎规格

### 7.1 流水线

```
bytes ──▶ ① Normalize ──▶ ② Probe(Parser 并行/短路) ──▶ ③ Rule Match ──▶ ④ Resolve ──▶ Result
          截断 8KiB        产出 Candidate{protocol, fields}   产出 Candidate{product,version,os,conf}   取最高分
          去尾部空白        失败即下一个 Parser                失败即下一个 Rule
```

1. **Normalize**：截断至 8192B；保留原始字节（`[]byte`），文本类匹配按 **latin-1 字节→rune 映射**执行，避免非 UTF-8 造成正则失配。
2. **Probe**：Parser 按 `priority` 降序尝试，命中即记录字段（不做最终判定，允许后续 Rule 覆盖 protocol）。
3. **Rule Match**：规则可匹配 `source: raw`（原始字节）或 `source: field`（Parser 抽出字段，如 `http.server`）。
4. **Resolve**：所有候选按 `confidence` 降序 → `priority` 降序 → 规则文件字典序，取第一个；无候选 → unknown。

### 7.2 规则文件规范

```yaml
# rules/ssh.yaml
version: 1
protocol: SSH
rules:
  - id: ssh.openssh
    priority: 100
    match:
      source: raw
      regex: '(?m)^SSH-(?P<protov>\d\.\d+)-(?P<product>[A-Za-z][A-Za-z0-9._\-]*?)[_\- ](?P<version>\d[0-9A-Za-z.\-]*)(?:[ \t]+(?P<comment>[^\r\n]*))?'
    fields:
      product:  '{{ .product }}'
      version:  '{{ .version }}'
      os_hint:  '{{ osFrom .comment }}'      # Ubuntu-3 → Ubuntu；Debian-1 → Debian；无 → ""
    confidence:
      base: 0.95
      if_empty: { version: 0.85 }
```

```yaml
# rules/http.yaml（节选：字段来源为 Parser 产出的 http.server，而非裸字节）
version: 1
protocol: HTTP
rules:
  - id: http.nginx
    priority: 100
    match:
      source: field
      field: http.server
      regex: '^(?P<product>nginx)/(?P<version>[\d.]+)(?:\s+\((?P<os>[^)]+)\))?'
    fields:
      product:  'nginx'                      # 归一化后的规范名
      version:  '{{ .version }}'
      os_hint:  '{{ osFrom .os }}'
    confidence: { base: 0.90 }
  - id: http.jetty
    priority: 100
    match:
      source: field
      field: http.server
      regex: '^(?P<product>Jetty)/(?P<version>[\d.]+)'
    fields: { product: 'Jetty', version: '{{ .version }}' }
    confidence: { base: 0.85 }               # JVM 容器版本语义较弱
  - id: http.generic
    priority: 10
    match:
      source: field
      field: http.status_line
      regex: '^HTTP/\d\.\d\s+\d{3}'
    fields: { product: '', version: '' }
    confidence: { base: 0.60 }               # 仅识别出协议
```

模板函数白名单（固定 4 个，避免规则里放任意逻辑）：`osFrom`（注释→发行版）、`trimV`（去 v 前缀）、`default`（空值兜底）、`lower`。

**Schema（启动强校验，逐字段类型检查，失败即退出）**

| 字段 | 类型 | 约束 |
|---|---|---|
| `version` | int | 必须为 1 |
| `protocol` | string | 枚举内 |
| `rules[].id` | string | 全局唯一 |
| `rules[].priority` | int | 0–1000，缺省 50 |
| `rules[].match.source` | enum | `raw` \| `field` |
| `rules[].match.regex` | string | 必须可编译；命名捕获组 ≤ 8 个 |
| `rules[].confidence.base` | float | `(0,1)` |

**加载优先级**：`go:embed rules/*.yaml`（编译期内置，保证镜像自包含）→ 启动时若 `RULES_DIR` 存在则**同名文件整体替换**、新增文件追加。热加载：`SIGHUP` 或 30s 轮询 mtime，失败保留旧规则并在 `/health` 报 `degraded`。

### 7.3 各协议识别规格

> 下列正则均为「必须实现」的基线，实现时可细化但不得降低召回。

#### 7.3.1 SSH

- 语法：RFC 4253 标识串 `SSH-<protoversion>-<softwareversion>[ <comments>]`，**可能不在首行**（前导可能有服务端噪声），需 `(?m)^`。
- 提取：`software` 形如 `OpenSSH_8.9p1` → 产品 `OpenSSH`、版本 `8.9p1`（下划线后为版本，`_` 前为产品）。
- `os_hint`：`comment` 中 `Ubuntu-3` / `Debian-1` / `FreeBSD-...` → 取首词；无 → `""`。
- 覆盖用例：`SSH-2.0-OpenSSH_8.9p1 Ubuntu-3`、`SSH-2.0-OpenSSH_9.3 Debian-1`、`SSH-1.99-OpenSSH_4.3`（协议版本 1.99 不影响识别）。
- 置信度：有版本 `0.95`；无版本 `0.85`；仅 `SSH-` 前缀无软件名 `0.60`。

#### 7.3.2 HTTP

- 语法：`^HTTP/\d\.\d\s+\d{3}`（大小写不敏感；兼容 `HTTP/2`、`HTTP/3` 文本形态）。
- 字段抽取：解析头部至空行，`Server`（取值首个产品 token）、`X-Powered-By`（仅辅助，不覆盖 `Server`）。
- 产品 token 语法：`Product/Version (Comment)`，如 `nginx/1.24.0`、`Apache/2.4.41 (Ubuntu)`、`Jetty/9.4.51`、`Microsoft-IIS/10.0`、`nginx/1.18.0 (Ubuntu)`。
- `os_hint`：括号注释中的发行版（`Ubuntu` → `Ubuntu`）；无 → `""`。
- 产品归一：`Apache`（非 `Apache httpd`）、`Microsoft-IIS`（保留连字符）、`nginx`（小写）。
- 置信度：
  - `Server` 命中已知产品 + 版本：`0.90`；
  - Java 容器类（Jetty/Tomcat/Undertow）版本语义较弱：`0.85`；
  - 只有产品无版本：`0.80`；
  - 仅状态行无 `Server`：`0.60`（product/version 为 `""`）。

#### 7.3.3 MySQL

- 语法：Initial Handshake Packet v10：`[3B payload_len LE][1B seq][1B protocol_version=0x0A][NUL 结尾 server_version]…`
- 解析必须**按字节**进行，不得先做 UTF-8 校验；容错：payload_len 与实际长度不符时仍尝试从偏移 4/5 处提取（`J\x00\x00\x00\n8.0.32\x00` 为本场景典型形态）。
- 提取：`server_version` → `product=MySQL`、`version=8.0.32`。
- 置信度：`0.90`（协议版本 0x0A + 可解析版本号）；仅 0x0A 无版本 `0.65`。
- 反例：任意 `\x00` 分隔的二进制串不应误判为 MySQL（要求 protocol_version 字节严格等于 `0x0A` 且其后为 `\d+\.\d+`）。

#### 7.3.4 Redis

- 语法：RESP 行首标记 `+`（简单串）/`-`（错误）/`:`（整数）/`$`（批量串）/`*`（数组）。
- 判定：标记 + 语义关键字。关键字表（`rules/redis.yaml`）：`NOAUTH`、`ERR`、`WRONGTYPE`、`NOPERM`、`unknown command`、`PONG`、`OK`。
- 版本：Redis 默认 banner 不含版本 → `version=""`、`product="Redis"`（不臆测）。
- 置信度：错误类关键字 `0.70`；`+PONG`/`+OK` 单独出现 `0.65`。
- 反例：普通以 `-` 开头的英文句子（如 `-bash: ...`）不得命中（要求 `-` 后紧跟全大写错误码或 `NOAUTH`/`ERR` 等）。

#### 7.3.5 FTP

- 语法：`^\d{3}[ -]`（RFC 959 三位应答码，`220` 为就绪）。
- 提取：产品关键字表 `ProFTPD` `vsFTPd` `Pure-FTPd` `FileZilla` `Serv-U` `Microsoft FTP`；版本 `\d+\.\d+(?:\.\d+)*`。
- 覆盖用例：`220 ProFTPD 1.3.7 Server (ProFTPD)`、`220 (vsFTPd 3.0.5)`、`220 Welcome to Pure-FTPd`。
- 置信度：产品 + 版本 `0.90`；仅产品 `0.80`；仅 `220` 欢迎语 `0.60`。

#### 7.3.6 TLS（扩展，可关闭）

- 语法：首字节 `0x16`（Handshake）+ 版本 `0x03 0x0X` + 长度字段，即 `\x16\x03[\x00-\x04]..`。
- 输出：`protocol=TLS`，`product=""`、`version=""`、`confidence=0.60`。
- 开关：`ENABLE_TLS_DETECT=1`（默认 1）。关闭后该输入降级 unknown。
- 理由：`\x16\x03\x01\x00\xa5…` 是明确的 TLS record 头，识别为 TLS 比 unknown 信息量更高；同时保留开关以适配不同判定口径。

#### 7.3.7 未知兜底

任何输入（空串、纯二进制、`QUIT\r\n`、非 banner 文本）在无规则命中时：

```json
{"ip":"1.2.3.23","port":12345,"protocol":"unknown","product":"","version":"","os_hint":"","confidence":0.0}
```

### 7.4 端口先验（弱）

端口**不参与**协议硬判定（评估数据端口可能非常规，如 8443 跑 nginx、8888 跑 IIS），也**不改变 `confidence` 数值**（保证与示例响应逐值一致）；仅在候选同分时决定排序：

| 情况 | tie-break 权重 |
|---|---|
| 端口与协议典型端口一致（22/SSH、80·443·8080·8443/HTTP、3306/MySQL、6379/Redis、21/FTP） | +1（优先） |
| 其他 | 0 |

### 7.5 置信度模型

```
confidence = clamp(base + Σmodifiers, 0.05, 0.99)
base      = 规则声明的基准分（见 §7.3）
modifiers = { 版本缺失: -0.10, 产品未知仅协议: -0.15 }
```

特例：协议本身不暴露版本（Redis、TLS）时，规则直接声明最终分，不套用「版本缺失」惩罚。端口先验不计入分数（§7.4）。

映射表（与示例响应一致，作为验收基线）：

| 证据强度 | 典型输入 | confidence |
|---|---|---|
| 协议标识 + 产品 + 版本 + 系统 | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3` | 0.95 |
| 协议 + 产品 + 版本（C 服务） | `Server: nginx/1.24.0`、`Apache/2.4.57`、MySQL 8.0.32、ProFTPD 1.3.7 | 0.90 |
| 协议 + 产品 + 版本（JVM 服务） | `Server: Jetty/9.4.51` | 0.85 |
| 协议 + 产品（无版本） | `ProFTPD` 无版本、Redis | 0.70–0.80 |
| 仅协议特征 | `HTTP/1.1 200 OK` 无 Server、TLS record | 0.60 |
| 无命中 | `QUIT\r\n` | 0.00 |

规则：**不得**为凑分而虚构版本；`confidence≥0.85` 必须同时具备 protocol + product + version。

---

## 8. 客户端规格

### 8.1 调用方式

```bash
# 容器内（推荐，评估者一条命令）
docker compose run --rm client -file /data/input.json -format table
docker compose run --rm client -file /data/input.json -format json > result.json

# 本机
go run ./cmd/client -file data/input.json -server http://127.0.0.1:8080
```

> `-out` 在容器内需挂载**可写**卷且目录对 uid `65532` 可写；因此 compose 默认不传 `-out`，用 stdout 重定向落盘（零权限问题）。

### 8.2 参数

| flag | 环境变量 | 默认 | 说明 |
|---|---|---|---|
| `-file` | `INPUT_FILE` | `data/input.json` | 输入文件路径（必填） |
| `-server` | `SERVER_URL` | `http://server:8080` | server 地址；**必须用 compose 服务名**，不写 `localhost` |
| `-out` | `OUTPUT_FILE` | `""` | 结果 JSON 落盘路径，空则不落盘 |
| `-format` | `OUTPUT_FORMAT` | `table` | `table` \| `json` |
| `-batch` | `BATCH_SIZE` | `500` | 单请求条数（≤10000） |
| `-timeout` | `HTTP_TIMEOUT` | `30s` | 单请求超时 |
| `-retry` | `HTTP_RETRY` | `3` | 指数退避重试（仅 5xx / 网络错误；4xx 不重试） |

### 8.3 行为

1. **就绪等待**：启动即轮询 `GET /health`（1s 间隔，上限 30s）直到 `status=="ok"`，再发业务请求。
   —— `depends_on: service_healthy` 已在编排层做一次保证，客户端再做一次，覆盖 `docker compose run` 不等待依赖的边界情况（双重保险，不冗余）。
2. 读取文件 → `jsonx` 宽松解码（与 server 共用同一实现）。
3. 校验条数；空文件视为 400 语义，客户端报错退出。
4. 按 `-batch` 分片，串行发送（避免打爆 server），汇总结果。
5. 输出：
   - `table`：定宽表格 + 末尾统计（总数 / unknown 数 / 各协议计数 / 平均置信度）；
   - `json`：与 server 响应同构的数组，直接打印（可管道给 `jq`）。
6. 结果顺序与输入一致（分片内保序，分片间顺序拼接）。
7. `-out` 落盘：`0644`，JSON 缩进 2 空格，末尾换行（便于 diff）；写失败仅告警不改变退出码。
8. 日志走 stderr，结果走 stdout（符合 Unix 习惯，可 `> result.json`）。

### 8.4 退出码

| 码 | 含义 |
|---|---|
| 0 | 成功（**即使含 unknown**） |
| 2 | 参数错误 / 文件不可读 / 非法 JSON |
| 3 | server 不可达或超时（重试耗尽） |
| 4 | server 返回 4xx |
| 5 | server 返回 5xx（重试耗尽） |

---

## 9. 配置项（server）

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `SERVER_ADDR` | `:8080` | 监听地址 |
| `RULES_DIR` | `/etc/bannerprint/rules.d` | 外部规则目录（不存在则仅用内置） |
| `MAX_BODY_BYTES` | `33554432` | 请求体上限 |
| `MAX_BATCH_ITEMS` | `10000` | 单批条数上限 |
| `MAX_BANNER_BYTES` | `8192` | 单条 banner 截断阈值 |
| `WORKERS` | `GOMAXPROCS` | 识别并发度 |
| `LOG_LEVEL` | `info` | `debug` 时输出命中规则与证据 |
| `LOG_FORMAT` | `json` | `json` \| `text` |
| `API_TOKEN` | `""` | 非空则要求 `Authorization: Bearer <token>` |
| `ENABLE_TLS_DETECT` | `1` | TLS 扩展识别开关 |
| `SHUTDOWN_TIMEOUT` | `10s` | 优雅退出排水时间 |

所有配置启动时打印一次（脱敏），便于排障。

---

## 10. 非功能需求

### 10.1 镜像构建（体现编译打包理解）

| 要求 | 做法 |
|---|---|
| 多阶段 | `golang:1.23-alpine` 构建 → `gcr.io/distroless/static-debian12:nonroot` 运行 |
| 静态二进制 | `CGO_ENABLED=0`、`-trimpath`、`-ldflags "-s -w -X main.version=$VERSION"` |
| 分层缓存 | 先 `COPY go.mod go.sum` + `go mod download`（`--mount=type=cache`），再 `COPY . .` |
| 单 Dockerfile 双目标 | `AS server` / `AS client` 两个 final stage，compose 用 `target:` 指定 |
| 镜像体积 | server ≤ 12 MB（distroless + 静态二进制） |
| `.dockerignore` | 排除 `.git` `data/` `*.md` `testdata/`（testdata 仅测试阶段需要） |
| 版本可追溯 | `ARG VERSION` + `ARG GIT_SHA` → ldflags → `/health.version` |
| 无 shell/包管理器 | distroless 无 bash/curl，降低逃逸面；健康检查用二进制自身子命令 |

### 10.2 运行时安全（compose 逐项落实）

```yaml
read_only: true                 # 根文件系统只读
cap_drop: ["ALL"]               # 丢弃全部 capability（server 仅需 bind 8080，非特权端口）
security_opt: ["no-new-privileges:true"]
user: "65532:65532"             # distroless nonroot
tmpfs: ["/tmp:size=16m,mode=1777"]
pids_limit: 256
mem_limit / cpus: 见 §11
```

- 不挂载 `docker.sock`、不使用 `privileged`、不使用 `network_mode: host`。
- 规则目录只读挂载（`:ro`）：即使容器被写入也无法篡改识别逻辑。
- 敏感信息仅通过 `environment` 注入，不写入镜像层。

### 10.3 容器间访问收敛

| 要求 | 做法 |
|---|---|
| client → server 用服务名 | `SERVER_URL=http://server:8080`，禁止 `localhost` / `127.0.0.1` / `host.docker.internal` |
| 网络分段 | `internal`（`internal: true`，无出网）承载 client↔server；`edge` 仅 server 加入并发布端口 |
| 最小暴露 | 只发布 server 的 8080，且默认绑定 `127.0.0.1`；client 不发布任何端口 |
| DNS 依赖而非 IP | 不使用 `container_name` 硬编码解析，使用 compose 默认服务发现 |
| 出网隔离 | server 无外部依赖（无 DB、无外呼），`internal` 网络保证即使被利用也无法外联 |

### 10.4 启动依赖与健康检测（真实生效，非装饰）

- `server.healthcheck.test = ["CMD", "/app/server", "healthcheck", "-url", "http://127.0.0.1:8080/health"]`
  —— 由二进制内置子命令发起真实 HTTP 请求并校验 `status=="ok" && checks.engine_ready==true`，不依赖 curl/wget（distroless 无此工具）。
- `interval: 5s`、`timeout: 2s`、`retries: 3`、`start_period: 5s`。
- `client.depends_on.server.condition: service_healthy` —— 等到**规则加载完成**才发请求，消除「容器已起但规则未就绪」竞态。
- `restart: unless-stopped` + healthcheck 使异常实例被编排层识别（compose 不自动重启 unhealthy，但 `docker compose up --wait` 会真实等待健康态，README 中以此作为验证命令）。

### 10.5 可观测性

- 结构化 JSON 日志（stdout）：`ts, level, msg, request_id, route, status, items, unknown, duration_ms`。
- `debug` 级输出每条命中的 `rule_id` 与证据（banner 前 64 字节，NUL 转义）；`info` 级**不打印完整 banner**（扫描数据可能含凭据）。
- 响应头回显 `X-Request-ID`，便于用户侧与日志对齐。
- 不引入 Prometheus 端点（保持路由白名单最小），指标通过日志聚合。

### 10.6 性能与容量

| 指标 | 目标 |
|---|---|
| 单条识别 P99 | ≤ 200 µs（纯内存正则 + 预编译） |
| 10000 条批量 | ≤ 2 s（4 vCPU 容器） |
| 内存常驻 | ≤ 64 MB（规则 + 引擎） |
| 并发 | 每请求内部 worker pool（`WORKERS`），无全局锁；正则全部 `MustCompile` 于加载期 |
| 稳定性 | 100% 输入不 panic；fuzz 目标 `FuzzFingerprint` 运行 60s 无崩溃 |

---

## 11. Docker Compose（交付核心）

```yaml
name: bannerprint

x-hardening: &hardening
  read_only: true
  cap_drop: ["ALL"]
  security_opt: ["no-new-privileges:true"]
  tmpfs: ["/tmp:size=16m,mode=1777"]
  logging:
    driver: json-file
    options: { max-size: "10m", max-file: "3" }

services:
  server:
    build:
      context: .
      target: server
      args:
        VERSION: ${VERSION:-dev}
    image: bannerprint/server:${VERSION:-dev}
    <<: *hardening
    user: "65532:65532"
    restart: unless-stopped            # 常驻服务才重启；client 是一次性容器，绝不能带 restart
    environment:
      SERVER_ADDR: ":8080"
      RULES_DIR: "/etc/bannerprint/rules.d"
      LOG_LEVEL: "${LOG_LEVEL:-info}"
      MAX_BATCH_ITEMS: "10000"
    volumes:
      - ./rules:/etc/bannerprint/rules.d:ro
    networks: [internal, edge]
    ports:
      - "${SERVER_BIND:-127.0.0.1}:${SERVER_PORT:-8080}:8080"
    healthcheck:
      test: ["CMD", "/app/server", "healthcheck", "-url", "http://127.0.0.1:8080/health"]
      interval: 5s
      timeout: 2s
      retries: 3
      start_period: 5s
    mem_limit: 256m
    cpus: 2.0
    pids_limit: 256

  client:
    build:
      context: .
      target: client
      args:
        VERSION: ${VERSION:-dev}
    image: bannerprint/client:${VERSION:-dev}
    <<: *hardening
    user: "65532:65532"
    profiles: ["client"]
    depends_on:
      server:
        condition: service_healthy
    environment:
      SERVER_URL: "http://server:8080"
    volumes:
      - ./data:/data:ro
    networks: [internal]
    command: ["-file", "/data/input.json", "-format", "table"]
    mem_limit: 128m
    cpus: 1.0

networks:
  internal:
    internal: true
  edge: {}
```

命令约定（写入 README 与 Makefile）：

| 场景 | 命令 |
|---|---|
| 起服务 | `docker compose up -d --build --wait` |
| 跑客户端 | `docker compose run --rm client -file /data/input.json` |
| 导出结果 | `docker compose run --rm client -file /data/input.json -format json > result.json` |
| 一键自测 | `make demo`（= 起服务 + 等健康 + 跑 client + 打印结果） |
| 跑测试 | `make test`（`docker build --target test` 内执行 `go test ./... -race`，无需本机 Go） |
| 关停 | `docker compose down -v` |

> 端口绑定：默认 `SERVER_BIND=127.0.0.1`（仅本机可访问，最小暴露）。需要从其他主机访问时显式 `SERVER_BIND=0.0.0.0 docker compose up -d`，README 中标注该权衡。
>
> 设计取舍：`client` 使用 `profiles: [client]`，避免 `docker compose up` 时一次性容器退出干扰编排状态；一键自测通过 `make demo` 保证「一条命令看结果」，两全。

---

## 12. 测试与验收

### 12.1 测试分层

| 层 | 内容 |
|---|---|
| 单测 | 每个 Parser 的表驱动用例（含二进制、超长、非 UTF-8、前后噪声） |
| 规则测试 | 加载全部 `rules/*.yaml` 并校验 schema；断言无重复 id、正则均可编译 |
| 契约测试 | `/fingerprint` 200/400/413/405、`/health` 200/503；1:1 保序 |
| 金标准测试 | `data/input.json` → `data/expected.json` 逐字段比对（§12.3） |
| 健壮性 | `FuzzFingerprint`；空 banner、`nil`、10MB 单条（截断后正常返回） |
| 部署验证 | `docker compose up --wait` 后 `curl /health` 与批量请求；容器 `read_only` 下运行不报错 |

所有测试必须 `go test ./... -race` 通过；测试不依赖网络。

### 12.2 评估维度自检表

| 评估关注点 | 本设计的落点 | 自检方式 |
|---|---|---|
| 容器间访问是否收敛 | §10.3：服务名 DNS、`internal` 网络、client 零端口、server 仅 127.0.0.1 发布 | `docker network inspect bannerprint_internal`（`Internal: true`）；client 能连通即证明走服务名解析 |
| 启动依赖是否真实 | §10.4：二进制内置 healthcheck 校验 `engine_ready`；`service_healthy` 门控 client | `docker inspect -f '{{.State.Health.Status}}'`；停掉 server 后 `docker compose run client` 应快速失败 |
| 镜像编译打包理解 | §10.1：多阶段、缓存挂载、静态二进制、distroless、ldflags 版本注入 | `docker image ls`（server ≤12MB）、`docker history` 层结构与构建缓存命中 |
| 运行权限收紧 | §10.2：nonroot 65532、`read_only`、`cap_drop ALL`、`no-new-privileges`、pids/内存上限 | `docker inspect -f '{{.HostConfig.ReadonlyRootfs}} {{.Config.User}}'` → `true 65532:65532`；`docker compose exec server /bin/sh` 应报 not found（无 shell） |
| 规则与代码解耦 | §3/§7.2：Parser(语法) 与 Rule(YAML) 分离；产品名字面量不出现在 Go 代码；SIGHUP 热加载；外部目录只读挂载覆盖 | `grep -riE 'nginx\|openssh\|proftpd' internal/` 应为空；改 YAML 后 `docker compose kill -s HUP server` 生效 |

### 12.3 自测金标准（`data/expected.json`，实现必须逐字段一致）

| # | ip | port | protocol | product | version | os_hint | conf |
|---|---|---|---|---|---|---|---|
| 1 | 1.2.3.4 | 22 | SSH | OpenSSH | 8.9p1 | Ubuntu | 0.95 |
| 2 | 1.2.3.5 | 80 | HTTP | nginx | 1.24.0 | | 0.90 |
| 3 | 1.2.3.6 | 443 | HTTP | Apache | 2.4.57 | | 0.90 |
| 4 | 1.2.3.7 | 3306 | MySQL | MySQL | 8.0.32 | | 0.90 |
| 5 | 1.2.3.8 | 6379 | Redis | Redis | | | 0.70 |
| 6 | 1.2.3.9 | 21 | FTP | ProFTPD | 1.3.7 | | 0.90 |
| 7 | 1.2.3.10 | 8080 | HTTP | Jetty | 9.4.51 | | 0.85 |
| 8 | 1.2.3.11 | 22 | SSH | OpenSSH | 9.3 | Debian | 0.95 |
| 9 | 1.2.3.12 | 80 | HTTP | nginx | 1.18.0 | Ubuntu | 0.90 |
| 10 | 1.2.3.13 | 443 | HTTP | Apache | 2.4.41 | Ubuntu | 0.90 |
| 11 | 1.2.3.14 | 3306 | MySQL | MySQL | 5.7.42 | | 0.90 |
| 12 | 1.2.3.15 | 6379 | Redis | Redis | | | 0.65 |
| 13 | 1.2.3.16 | 21 | FTP | vsFTPd | 3.0.5 | | 0.90 |
| 14 | 1.2.3.17 | 8443 | HTTP | nginx | 1.25.3 | | 0.90 |
| 15 | 1.2.3.18 | 22 | SSH | OpenSSH | 4.3 | | 0.95 |
| 16 | 1.2.3.19 | 9999 | TLS | | | | 0.60 |
| 17 | 1.2.3.20 | 8888 | HTTP | Microsoft-IIS | 10.0 | | 0.90 |
| 18 | 1.2.3.21 | 6379 | Redis | Redis | | | 0.70 |
| 19 | 1.2.3.22 | 21 | FTP | Pure-FTPd | | | 0.80 |
| 20 | 1.2.3.23 | 12345 | unknown | | | | 0.00 |

前 7 条与题目示例响应的字段值**完全一致**（含 confidence），作为对齐基准；其余 13 条为本系统扩展口径。

### 12.4 验收判定

- 必过：20 条中 protocol/product/version/os_hint 全对，且前 7 条 confidence 与示例一致。
- 必过：未识别输入返回 200 + unknown，进程存活（`/health` 仍 ok）。
- 必过：`docker compose up -d --build --wait` 在干净机器（仅 Docker）上 90s 内进入 healthy。
- 加分：未知数据（评估者的第二套）中非常规端口、带噪声前缀、无版本 banner 仍能正确降级而非误判。

---

## 13. 实施计划（30 分钟时间盒）

| 时段 | 交付 |
|---|---|
| T+0–4 | 骨架：`go.mod`、model/config/jsonx、server 路由与中间件、`/health` |
| T+4–14 | 5 个 Parser + `rules/*.yaml` + engine 仲裁；对 20 条自测全绿 |
| T+14–20 | client、Makefile、`docker-compose.yml`、Dockerfile（双 target） |
| T+20–25 | 单测/金标准测试/fuzz 冒烟；`docker compose up --wait` + curl 验证 |
| T+25–30 | README（部署/接口/规则扩展/设计决策）、提交并推送 GitHub，回传仓库地址 |

时间盒硬约束：T+28 必须开始 `git push`（推送耗时不可控），任何未完成项写进 README 的 Known Limitations，不得留到截止后。

---

## 14. 风险与对策

| 风险 | 影响 | 对策 |
|---|---|---|
| 输入 JSON 含非法 `\xNN` 转义 | 标准库直接报错，整批失败 | `internal/jsonx` 宽松解码（§4.4），client/server 共用 |
| 评估数据端口非常规 | 依赖端口判协议导致误判 | 端口仅作 tie-break（§7.4） |
| 二进制 banner 被 UTF-8 校验破坏 | MySQL 识别失败 | 全链路 `[]byte`，正则按 latin-1 映射 |
| 规则与代码耦合被扣分 | 评估重点失分 | Parser/Rule 分层 + `grep` 自检（§12.2） |
| distroless 拉取失败（网络受限） | 构建失败 | README 提供 `DOCKER_BASE=alpine` 备用方案（同一 Dockerfile `ARG` 切换） |
| 评估者严格比对字段集合 | 多字段被判错 | 默认响应仅 7 字段，调试信息走日志/`?explain=1` |
| 推送耗时挤压 | 未按时提交 | T+28 强制推送；先推可运行版本，再迭代 |

---

## 15. 附录：端到端示例

```bash
$ docker compose up -d --build --wait
[+] Running 2/2
 ✔ Network bannerprint_internal  Created
 ✔ Container bannerprint-server-1  Healthy

$ docker compose run --rm client -file /data/input.json
IP          PORT   PROTOCOL  PRODUCT        VERSION  OS_HINT  CONF
1.2.3.4     22     SSH       OpenSSH        8.9p1    Ubuntu   0.95
1.2.3.5     80     HTTP      nginx          1.24.0            0.90
...
1.2.3.23    12345  unknown                                   0.00
── 20 items | 1 unknown | SSH 3 · HTTP 7 · MySQL 2 · Redis 3 · FTP 3 · TLS 1 · unknown 1 | avg conf 0.81

$ curl -s http://127.0.0.1:8080/health | jq .status
"ok"
```

---

## 16. 需求追溯矩阵

| 题目要求 | 本文落点 | 验收证据 |
|---|---|---|
| R1 server 提供 `POST /fingerprint`、`GET /health`；client 为独立程序，读本地 JSON、发给 server、展示结果 | §4.2 / §4.3 / §8 | `curl` 两接口；`docker compose run --rm client` 输出表格 |
| R2 结果 7 字段；认不出返回 `protocol:"unknown"`，不得报错崩溃 | §5 / §4.2 状态码 / §7.3.7 / §3 故障隔离 | 20 条自测含 1 条 unknown，HTTP 200、`/health` 仍 ok |
| R3 至少识别 SSH、HTTP(nginx/Apache/Jetty)、MySQL、Redis、FTP | §7.3.1–7.3.5 + `rules/*.yaml` | §12.3 金标准全绿 |
| R4 Docker Compose 一键启动；生产级：访问收敛 / 真实健康检测 / 镜像构建 / 权限收紧 / 规则与代码解耦 | §10（全节）/ §11 / §12.2 | 自检表 5 项逐条可复现 |
| R5 30 分钟内完成并推送 GitHub | §13 时间盒 | 提交时间戳 + 仓库可克隆 |
| R6 全程仅通过 AI 编程工具操作（含 GitHub、中间件、运行环境），无人工编辑 | 工程约束：所有命令（`git`、`docker`、文件写入）均由 agent 工具链执行，人只输入提示词 | 屏录 + agent 会话记录 |

> 仓库根目录即 §6 所示的 `bannerprint/` 目录本身（`docker compose up` 在仓库根执行），不额外套一层子目录。
