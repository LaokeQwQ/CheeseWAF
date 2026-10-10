# 环境变量（CHEESEWAF_*）

以下变量来自源码里 `grep -rnoE 'CHEESEWAF_[A-Z_]+'` 的实际出现位置。文档只描述作用、默认值与示例，具体语义仍以对应源码为准（不确定处会在条目内标注「以源码为准」）。

## 应用运行时变量

这些变量会影响 CheeseWAF 服务进程的运行行为；未设置时走源码内置默认值。

| 变量 | 作用 | 默认值 | 示例 |
|---|---|---|---|
| `CHEESEWAF_SETUP_TOKEN` | 首次安装阶段的准入令牌。服务首次启动时会把它写入运行时数据目录下权限为 `0600` 的 `setup.token`；未设置时自动生成高熵 Token。API 请求通过 `X-CheeseWAF-Setup-Token` 头携带，服务会在每次 setup 请求时读取当前 Token，因此 `cheesewaf setup token reset` 可在不停服的情况下立即撤销旧值且不需要输入旧 Token；`rotate` 仍为兼容别名。Token 按原值严格比较，前后空格和控制字符会被拒绝。环境变量只适合受控的 CI/临时启动场景，不应写入版本库或命令行参数。 | 空，初次安装前自动生成 | `export CHEESEWAF_SETUP_TOKEN=...` |
| `CHEESEWAF_WEB_DIR` | 管理后台 Web 静态资源目录。`resolveWebDir()` 把它作为第一个候选路径；未设置时会依次尝试可执行文件旁的 `web/dist`、配置目录旁的 `web/dist`、`/usr/share/cheesewaf/web`、`/opt/cheesewaf/web/dist`、`./web/dist` 等，都找不到则回退到内嵌 FS（`webui.FS()`）。 | 空 = 自动探测 / 内嵌 | `/usr/share/cheesewaf/web` |
| `CHEESEWAF_CONFIG` | 主 CLI、桌面控制器和 `healthcheck` 的配置文件路径覆盖；容器入口点 `deploy/docker/entrypoint.sh` 也用它生成/复制配置文件。 | 空；开发 profile 使用数据目录下的 `config/cheesewaf.yaml`，安装器 profile 使用 `/etc/cheesewaf/cheesewaf.yaml` | `/etc/cheesewaf/cheesewaf.yaml` |
| `CHEESEWAF_DATA_DIR` | CLI、桌面控制器和安装器的数据目录覆盖；未设置时使用当前运行 profile 的默认目录。 | 空 = `./data`（开发）或安装器 profile 的 `/var/lib/cheesewaf` | `/srv/cheesewaf` |
| `CHEESEWAF_LANG` | CLI 界面语言。优先级：flag > `CHEESEWAF_LANG` > `dataDir/cli.lang` > 系统 locale > `en`（`internal/cli/clilang/lang.go`）。支持 `en` 与 `zh-CN`；`zh`、`zh-CN`、`zh-Hans`、`cn` 等都会映射成 `zh-CN`。 | 空 = 回退到系统语言或 `en` | `export CHEESEWAF_LANG=zh-CN` |
| `CHEESEWAF_ADMIN_PUBLIC_HOST` | 公网管理地址的展示主机名/IP；安装器写入 systemd 环境文件，避免把 `0.0.0.0` 写进一次性 setup URL。 | 空 = 使用本机公网接口候选；NAT/域名场景建议显式设置 | `export CHEESEWAF_ADMIN_PUBLIC_HOST=waf.example.com` |
| `CHEESEWAF_CLUSTER_CONTROLLER` | 集群 `monitor-node` 心跳的 controller 地址。优先级：flag `--controller` > 环境变量 > `cluster.interconnect.advertise_addr`（缺 scheme 时补 `https://`），都不存在则报错（`internal/cli/cluster.go`）。 | 空 = 回退到集群互联地址 | `https://controller.example:9443` |
| `CHEESEWAF_DEPLOY_BINARY` | 集群部署时当作安装源二进制（上传到远端）。`openInstallBinary()` 读取；未设置则使用当前正在运行的二进制（`os.Executable()`）。必须满足：常规文件、非空、不超大小上限、路径不含空字符/换行（`internal/cluster/deploy/ssh.go`）。 | 当前可执行文件 | `/usr/local/bin/cheesewaf` |
| `CHEESEWAF_PROBE_MEMORY_MB` | 覆盖安装探针里对主机内存的估算（MB），用于硬件档位（低/中/高）分类。设置正数即采用，否则回退到保守的 4096 并配合 CPU/磁盘结果（`internal/setup/probe.go`）。 | 未设置时按 4096 | `export CHEESEWAF_PROBE_MEMORY_MB=8192` |
| `CHEESEWAF_FILE_SINK_CACHE_LIMIT` | 日志文件 sink 的近期缓存条目数上限（加速未写入磁盘时的日志查询）。解析失败或 <0 时回退默认（`internal/storage/log_sink/file.go`）。 | 20000 | `export CHEESEWAF_FILE_SINK_CACHE_LIMIT=50000` |
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
| `CHEESEWAF_ADMIN_LISTEN` | `scripts/ci/install-linux.sh` | 管理监听地址，默认读取发布包 `configs/cheesewaf.yaml` 的 `server.admin_listen`（当前模板为 `0.0.0.0:9443`）；公网监听必须保持管理 TLS 开启 |
| `CHEESEWAF_SECURITY_ENTRY` | `scripts/ci/install-linux.sh` | 安装期安全入口后缀，仅接受 8-64 位 ASCII 字母和数字；留空随机生成 |
| `CHEESEWAF_DETECT_PUBLIC_IP` | `scripts/ci/install-linux.sh` | 设为 `1` 才允许安装器通过 HTTPS 请求 `api.ipify.org` 探测出口地址；默认不外呼，优先使用本机公网接口或 `CHEESEWAF_ADMIN_PUBLIC_HOST` |
| `CHEESEWAF_SHOW_SECRETS` | `scripts/ci/install-linux.sh` | 设为 `1` 才在非交互 stdout 显示安全入口和一次性 URL；默认只写入 root-only 回执文件 |
| `CHEESEWAF_NO_START` | `scripts/ci/install-linux.sh` | 设为 `1` 时只安装文件，不调用 systemd 启动服务 |
| `CHEESEWAF_DOCKER_TAG` | `scripts/ci/docker-build.sh` | 镜像 tag，默认 `cheesewaf:ci` |
| `CHEESEWAF_DOCKER_PLATFORMS` | `scripts/ci/docker-build.sh` | buildx 目标平台，默认 `linux/amd64,linux/arm64` |
| `CHEESEWAF_GO_IMAGE` / `CHEESEWAF_NODE_IMAGE` / `CHEESEWAF_RUNTIME_IMAGE` | `scripts/ci/docker-build.sh` | 各构建阶段基础镜像覆盖 |
| `CHEESEWAF_SKIP_OUTBOUND_TLS` | `scripts/ci/docker-build.sh` | 置为 `1` 则跳过容器出站 HTTPS 检查，默认 `0` |
| `CHEESEWAF_OUTBOUND_TLS_URL` | `scripts/ci/docker-build.sh` | 出站 HTTPS 检查 URL，默认 `https://example.com` |
| `CHEESEWAF_VERSION_PREFIX` | `scripts/ci/package-release.sh` | 发布版本前缀，默认读取 `scripts/ci/product-version`（当前为 `0.4.2`）；Beta/预发布标签由发布通道追加 |
| `CHEESEWAF_REF_NAME` / `CHEESEWAF_COMMIT` / `CHEESEWAF_RUN_NUMBER` / `CHEESEWAF_BUILD_TIME` | `scripts/ci/package-release.sh`、`.github/workflows/ci.yml`、`.forgejo/workflows/ci.yml` | 发布元数据（分支/提交/构建号/时间） |
| `CHEESEWAF_RELEASE_PROFILE` | `scripts/ci/release-targets.sh`、CI workflows | 发布目标档位。`server` 默认生成 Linux x86_64、Linux ARM64 和 Linux LoongArch64；`full` 默认保留全部跨平台目标 |
| `CHEESEWAF_RELEASE_DIR` / `CHEESEWAF_RELEASE_WORK_DIR` / `CHEESEWAF_TARGETS` | `scripts/ci/package-release.sh`、CI workflows | 发布输出目录、工作目录与目标平台列表。设置 `CHEESEWAF_TARGETS` 时会覆盖档位默认目标；`server` 档位只接受三个 Linux 目标，拒绝 Windows/macOS 目标 |
| `CHEESEWAF_REQUIRE_SIGNING` / `CHEESEWAF_SIGNING_SCOPE` | `scripts/ci/verify-release.sh`、CI workflows | 发行物签名检查模式与范围。稳定服务器版使用 `1` + `server`，强制服务器发行物边界并跳过桌面证书检查；完整档位可使用 `all`、`windows` 或 `macos` |
| `CHEESEWAF_SETUP_TOKEN` | `scripts/ci/docker-build.sh`、`scripts/ci/verify-ci-static.sh` | CI 冒烟/静态验证时固定首次安装令牌（运行时同名字段见上表） |
| `CHEESEWAF_SQLMAP_DOCKER_IMAGE` / `CHEESEWAF_XSSTRIKE_DOCKER_IMAGE` / `CHEESEWAF_NUCLEI_DOCKER_IMAGE` / `CHEESEWAF_ZAP_DOCKER_IMAGE` / `CHEESEWAF_TEST_SCANNER_IMAGE` | `cmd/cheesewaf-corpus/gate.go`、`cmd/cheesewaf-corpus/main_test.go` | 语料扫描工具镜像覆盖 |
| `CHEESEWAF_CAPTCHA_BROWSER` / `CHEESEWAF_CAPTCHA_BROWSER_HARNESS` / `CHEESEWAF_CAPTCHA_HARNESS` / `CHEESEWAF_CAPTCHA_HARNESS_REPORT` / `CHEESEWAF_CAPTCHA_INTEGRATION` | `internal/captcha`、`scripts/e2e/captcha-*` | captcha 行为/集成测试工具 |
| `CHEESEWAF_TOKEN` | `web/scripts/playwright-*.mjs` | 前端 Playwright 测试访问令牌 |

> 注：以上为源码中实际出现的 CHEESEWAF_* 变量；默认值与语义以源码为准。

## 重置首次安装 Token

处于首次安装向导阶段（数据目录中不存在 `.setup_complete` 且管理员表为空）时，可使用：

```bash
cheesewaf setup token reset
```

标准路径下不需要任何参数或旧 Token；仅当配置和数据目录被自定义时，才添加 `--config` / `--data-dir`。命令会原子替换运行时 `setup.token`、立即使旧 Token 失效，并重新写入短期 `setup.url`。默认输出不包含 Token；只有在确认终端不会被记录时才使用 `--show`。初始化完成后，重置命令会拒绝执行；完成向导也会删除 `setup.token` 与 `setup.url`。旧命令 `cheesewaf setup token rotate` 仍作为兼容别名保留。
