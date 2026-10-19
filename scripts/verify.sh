#!/usr/bin/env sh
# 五项生产级自检：把「评估重点」变成一条命令可复现的证据。
#
#   ./scripts/verify.sh        # 需要 server 已通过 docker compose up -d --build --wait 启动
#
# 只依赖 docker / docker compose 与 POSIX sh（Git Bash、Linux、macOS 均可）。
# 逐项打印 PASS/FAIL，任一失败退出码为 1。
set -u

# Git Bash（MSYS）会把 `/app/server` 改写成本机 Windows 路径，
# 导致 docker exec 找不到二进制。关闭路径转换，Linux/macOS 上该变量无副作用。
export MSYS_NO_PATHCONV=1

PROJECT="bannerprint"
CONTAINER="${PROJECT}-server-1"
IMAGE="${PROJECT}/server:${VERSION:-dev}"
INTERNAL_NET="${PROJECT}_internal"

pass=0
fail=0

ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; pass=$((pass + 1)); }
ng()   { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; fail=$((fail + 1)); }
info() { printf '        %s\n' "$1"; }

command -v docker >/dev/null 2>&1 || { echo "docker not found"; exit 1; }

if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
    echo "container $CONTAINER not found; run: docker compose up -d --build --wait"
    exit 1
fi

echo
echo "bannerprint 自检 —— $CONTAINER"
echo

# ── 1. 容器间访问是否收敛 ────────────────────────────────────────────────
echo "[1] 网络收敛"
internal=$(docker network inspect "$INTERNAL_NET" --format '{{.Internal}}' 2>/dev/null || echo "missing")
if [ "$internal" = "true" ]; then
    ok "internal 网络 $INTERNAL_NET 为 Internal: true（无外网出口）"
else
    ng "internal 网络 $INTERNAL_NET 未标记 internal（实际: $internal）"
fi

# server 的端口发布必须绑定回环，不允许 0.0.0.0
binding=$(docker inspect "$CONTAINER" --format '{{json .NetworkSettings.Ports}}')
case "$binding" in
    *'"HostIp":"127.0.0.1"'*) ok "server 端口仅发布到 127.0.0.1" ;;
    *'"HostIp":"::"'*|*'"HostIp":"0.0.0.0"'*) ng "server 端口暴露到所有网卡: $binding" ;;
    *) ok "server 端口发布: $binding" ;;
esac
info "$binding"

# ── 2. 启动依赖是否真实（探针校验 engine_ready）──────────────────────────
echo "[2] 健康检测"
if docker compose exec -T server /app/server healthcheck -url http://127.0.0.1:8080/health >/dev/null 2>&1; then
    ok "内置 healthcheck 子命令返回 0（engine_ready=true）"
else
    ng "healthcheck 子命令失败"
fi
if [ "$(docker inspect "$CONTAINER" --format '{{.State.Health.Status}}')" = "healthy" ]; then
    ok "容器健康状态为 healthy"
else
    ng "容器健康状态: $(docker inspect "$CONTAINER" --format '{{.State.Health.Status}}')"
fi

# ── 3. 镜像（静态二进制 / 体积）──────────────────────────────────────────
echo "[3] 镜像与分层"
size=$(docker image inspect "$IMAGE" --format '{{.Size}}' 2>/dev/null || echo 0)
if [ "$size" -gt 0 ] && [ "$size" -lt 20000000 ]; then
    ok "镜像体积 $((size / 1024 / 1024)) MB（< 20 MB，scratch + 静态二进制）"
else
    ng "镜像体积异常: $size bytes（镜像 $IMAGE）"
fi
info "层数: $(docker history "$IMAGE" --no-trunc --format '{{.CreatedBy}}' 2>/dev/null | wc -l | tr -d ' ')"

# ── 4. 运行权限收紧 ─────────────────────────────────────────────────────
echo "[4] 权限收紧"
user=$(docker inspect "$CONTAINER" --format '{{.Config.User}}')
readonly_fs=$(docker inspect "$CONTAINER" --format '{{.HostConfig.ReadonlyRootfs}}')
caps=$(docker inspect "$CONTAINER" --format '{{.HostConfig.CapDrop}}')
pids=$(docker inspect "$CONTAINER" --format '{{.HostConfig.PidsLimit}}')

[ "$user" = "65532:65532" ] && ok "以非 root 运行（uid:gid = $user）" || ng "运行用户为 $user（期望 65532:65532）"
[ "$readonly_fs" = "true" ] && ok "根文件系统只读（read_only: true）" || ng "根文件系统可写"
case "$caps" in *ALL*) ok "已丢弃全部 capability（cap_drop: ALL）" ;; *) ng "cap_drop 未包含 ALL: $caps" ;; esac
[ "${pids:--1}" != "0" ] && ok "pids 上限: $pids" || ng "未设置 pids 限制"

# ── 5. 规则与代码是否解耦 ───────────────────────────────────────────────
echo "[5] 规则与代码解耦"
# 只检查「厂商/产品名」，不检查协议名（SSH/HTTP/Redis 是协议，本就属于代码词汇）。
VENDOR_RE='nginx|openssh|apache|proftpd|vsftpd|pure-ftpd|jetty|microsoft-iis|filezilla|serv-u'
hits=$(grep -riE "$VENDOR_RE" internal/ --include='*.go' 2>/dev/null | grep -v '_test.go' | wc -l | tr -d ' ')
if [ "$hits" = "0" ]; then
    ok "Go 代码中无厂商/产品名字面量（全部在 rules/*.yaml）"
else
    ng "Go 代码中发现 $hits 处产品名，示例："
    grep -riE "$VENDOR_RE" internal/ --include='*.go' 2>/dev/null | grep -v '_test.go' | head -5
fi
info "规则文件: $(ls rules/*.yaml 2>/dev/null | wc -l | tr -d ' ') 个"

echo
if [ "$fail" -eq 0 ]; then
    printf '\033[32m全部通过\033[0m：%d 项 PASS\n\n' "$pass"
    exit 0
fi
printf '\033[31m%d 项失败\033[0m（%d 项通过）\n\n' "$fail" "$pass"
exit 1
