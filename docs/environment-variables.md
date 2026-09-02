# 环境变量（CHEESEWAF_*）

以下变量来自源码里 `grep -rnoE 'CHEESEWAF_[A-Z_]+'` 的实际出现位置。文档只描述作用、默认值与示例，具体语义仍以对应源码为准（不确定处会在条目内标注「以源码为准」）。

## 应用运行时变量

这些变量会影响 CheeseWAF 服务进程的运行行为；未设置时走源码内置默认值。

| 变量 | 作用 | 默认值 | 示例 |
|---|---|---|---|
| `CHEESEWAF_SETUP_TOKEN` | 首次安装（setup）阶段允许写操作的一次性准入令牌。读取自环境变量（`internal/cli/service.go:140`）；若为空且安装尚未完成，服务会自动生成一个高熵令牌并通过 setup 地址的 `#setup_token=` 片段暴露。请求需带 `X-CheeseWAF-Setup-Token` 头（`internal/api/handler/setup_wizard.go:59`）。 | 空，安装未完成时自动生成 | `export CHEESEWAF_SETUP_TOKEN=...` |
| `CHEESEWAF_WEB_DIR` | 管理后台 Web 静态资源目录。`resolveWebDir()` 把它作为第一个候选路径；未设置时会依次尝试可执行文件旁的 `web/dist`、配置目录旁的 `web/dist`、`/usr/share/cheesewaf/web`、`/opt/cheesewaf/web/dist`、`./web/dist` 等，都找不到则回退到内嵌 FS（`webui.FS()`）。 | 空 = 自动探测 / 内嵌 | `/usr/share/cheesewaf/web` |
| `CHEESEWAF_CONFIG` | 配置文件路径，`healthcheck` 子命令在 config flag 之后把它作为回退候选（`internal/cli/healthcheck.go:52`）；容器入口点 `deploy/docker/entrypoint.sh` 也用它生成/复制配置文件。 | 空；`healthcheck` 走 config flag / 数据目录默认路径。Docker 默认 `/var/lib/cheesewaf/config/cheesewaf.yaml` | `/etc/cheesewaf/cheesewaf.yaml` |
| `CHEESEWAF_LANG` | CLI 界面语言。优先级：flag > `CHEESEWAF_LANG` > `dataDir/cli.lang` > 系统 locale > `en`（`internal/cli/clilang/lang.go`）。支持 `en` 与 `zh-CN`；`zh`、`zh-CN`、`zh-Hans`、`cn` 等都会映射成 `zh-CN`。 | 空 = 回退到系统语言或 `en` | `export CHEESEWAF_LANG=zh-CN` |
| `CHEESEWAF_CLUSTER_CONTROLLER` | 集群 `monitor-node` 心跳的 controller 地址。优先级：flag `--controller` > 环境变量 > `cluster.interconnect.advertise_addr`（缺 scheme 时补 `https://`），都不存在则报错（`internal/cli/cluster.go`）。 | 空 = 回退到集群互联地址 | `https://controller.example:9443` |
| `CHEESEWAF_DEPLOY_BINARY` | 集群部署时当作安装源二进制（上传到远端）。`openInstallBinary()` 读取；未设置则使用当前正在运行的二进制（`os.Executable()`）。必须满足：常规文件、非空、不超大小上限、路径不含空字符/换行（`internal/cluster/deploy/ssh.go`）。 | 当前可执行文件 | `/usr/local/bin/cheesewaf` |
| `CHEESEWAF_PROBE_MEMORY_MB` | 覆盖安装探针里对主机内存的估算（MB），用于硬件档位（低/中/高）分类。设置正数即采用，否则回退到保守的 4096 并配合 CPU/磁盘结果（`internal/setup/probe.go`）。 | 未设置时按 4096 | `export CHEESEWAF_PROBE_MEMORY_MB=8192` |
| `CHEESEWAF_FILE_SINK_CACHE_LIMIT` | 日志文件 sink 的近期缓存条目数上限（加速未落盘查询）。解析失败或 <0 时回退默认（`internal/storage/log_sink/file.go`）。 | 20000 | `export CHEESEWAF_FILE_SINK_CACHE_LIMIT=50000` |
| `CHEESEWAF_FILE_SINK_CACHE_BYTES` | 同一近期缓存的字节上限；会被钳制到最大 256 MiB（`maxFileSinkCacheBytes`）。解析失败或 <0 时回退默认（`internal/storage/log_sink/file.go`）。 | 64 MiB（`64 << 20 = 67108864`） | `export CHEESEWAF_FILE_SINK_CACHE_BYTES=134217728` |

## 构建 / CI / 测试工具变量（非运行时）

以下变量来自源码 grep，但只被构建脚本、CI 工作流或测试工具消费，不用于正常服务运行；默认值均以源码为准。

| 变量 | 位置 | 作用 |
|---|---|---|
| `CHEESEWAF_UID` / `CHEESEWAF_GID` | `deploy/docker/Dockerfile`、`scripts/ci/docker-build.sh`、`deploy/docker/docker-compose.yml` | 容器镜像内非 root 运行用户的 UID/GID，默认 10001 |
| `CHEESEWAF_PREFIX` | `scripts/ci/install-linux.sh` | Linux 安装前缀，默认 `/usr/local` |
| `CHEESEWAF_WEB_DIR` | `scripts/ci/install-linux.sh` | 安装 Web 目录，默认 `/usr/share/cheesewaf/web`（与运行时同名变量见上表） |
| `CHEESEWAF_CONFIG_DIR` | `scripts/ci/install-linux.sh` | 配置目录，默认 `/etc/cheesewaf` |
| `CHEESEWAF_DATA_DIR` | `scripts/ci/install-linux.sh` | 数据目录，默认 `/var/lib/cheesewaf` |
| `CHEESEWAF_LOG_DIR` | `scripts/ci/install-linux.sh` | 日志目录，默认 `/var/log/cheesewaf` |
| `CHEESEWAF_UNIT_DIR` | `scripts/ci/install-linux.sh` | systemd unit 目录，默认 `/etc/systemd/system` |
| `CHEESEWAF_DOCKER_TAG` | `scripts/ci/docker-build.sh` | 镜像 tag，默认 `cheesewaf:ci` |
| `CHEESEWAF_DOCKER_PLATFORMS` | `scripts/ci/docker-build.sh` | buildx 目标平台，默认 `linux/amd64,linux/arm64` |
| `CHEESEWAF_GO_IMAGE` / `CHEESEWAF_NODE_IMAGE` / `CHEESEWAF_RUNTIME_IMAGE` | `scripts/ci/docker-build.sh` | 各构建阶段基础镜像覆盖 |
| `CHEESEWAF_SKIP_OUTBOUND_TLS` | `scripts/ci/docker-build.sh` | 置为 `1` 则跳过容器出站 HTTPS 检查，默认 `0` |
| `CHEESEWAF_OUTBOUND_TLS_URL` | `scripts/ci/docker-build.sh` | 出站 HTTPS 检查 URL，默认 `https://example.com` |
| `CHEESEWAF_VERSION_PREFIX` | `scripts/ci/package-release.sh` | 发布版本前缀，默认 `0.1.0` |
| `CHEESEWAF_REF_NAME` / `CHEESEWAF_COMMIT` / `CHEESEWAF_RUN_NUMBER` / `CHEESEWAF_BUILD_TIME` | `scripts/ci/package-release.sh`、`.github/workflows/ci.yml`、`.forgejo/workflows/ci.yml` | 发布元数据（分支/提交/构建号/时间） |
| `CHEESEWAF_RELEASE_DIR` / `CHEESEWAF_RELEASE_WORK_DIR` / `CHEESEWAF_TARGETS` | `scripts/ci/package-release.sh`、CI workflows | 发布输出目录、工作目录与目标平台列表 |
| `CHEESEWAF_SETUP_TOKEN` | `scripts/ci/docker-build.sh`、`scripts/ci/verify-ci-static.sh` | CI 冒烟/静态验证时固定首次安装令牌（运行时同名字段见上表） |
| `CHEESEWAF_SQLMAP_DOCKER_IMAGE` / `CHEESEWAF_XSSTRIKE_DOCKER_IMAGE` / `CHEESEWAF_NUCLEI_DOCKER_IMAGE` / `CHEESEWAF_ZAP_DOCKER_IMAGE` / `CHEESEWAF_TEST_SCANNER_IMAGE` | `cmd/cheesewaf-corpus/gate.go`、`cmd/cheesewaf-corpus/main_test.go` | 语料扫描工具镜像覆盖 |
| `CHEESEWAF_CAPTCHA_BROWSER` / `CHEESEWAF_CAPTCHA_BROWSER_HARNESS` / `CHEESEWAF_CAPTCHA_HARNESS` / `CHEESEWAF_CAPTCHA_HARNESS_REPORT` / `CHEESEWAF_CAPTCHA_INTEGRATION` | `internal/captcha`、`scripts/e2e/captcha-*` | captcha 行为/集成测试工具 |
| `CHEESEWAF_AGENT_EYES` | `web/vite.config.ts` | 前端构建/开发时是否接入 agent-eyes 的开关 |
| `CHEESEWAF_TOKEN` | `web/scripts/playwright-*.mjs` | 前端 Playwright 测试访问令牌 |

> 注：以上为源码中实际出现的 CHEESEWAF_* 变量；默认值与语义以源码为准。
