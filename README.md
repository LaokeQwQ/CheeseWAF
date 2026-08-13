<p align="center">
  <img src="web/public/cheesewaf-logo.png" alt="CheeseWAF 标志" width="160">
</p>

<h1 align="center">CheeseWAF</h1>

<p align="center">使用 Go 构建的自托管 Web 应用防火墙</p>

CheeseWAF 部署在客户端与源站之间。它通过反向代理检查请求和响应，并提供统一的管理 API、Web 控制台和终端管理入口。

> 项目目前处于预发布阶段。配置格式和接口仍可能调整，请先在受控环境中验证，再用于生产流量。

## 核心能力

- **Web 攻击防护**：检测 SQL 注入、XSS、RCE、LFI、XXE、SSRF、NoSQL 注入和 SSTI，并支持自定义规则与响应检查。
- **Bot 与流量控制**：提供限流、JS 工作量证明、图片验证码、滑块验证码和排队室。
- **API 安全**：支持请求结构校验、端点限流，以及基于 HMAC、PEM 或 JWKS 的 JWT 验证。
- **访问控制**：支持全局、站点和路径级规则，以及 IP 信誉、GeoIP 和按供应商绑定 CIDR 的可信代理识别。
- **统一管理**：同一套数据可供 Web 控制台、REST API 和 `waf-cli` TUI 使用，并带有 RBAC、会话撤销和审计日志。
- **监控与分析**：提供 Prometheus 指标、多种日志后端、安全报告、攻击地图和可选的 LLM 辅助分析。
- **部署与集群**：提供 Docker、systemd 和 Windows 构建文件，并包含节点加入、证书轮换和滚动升级能力。
- **可重复验证**：内置语义攻击样本回放工具，可测试进程内检测器或已部署的数据平面。

## 工作方式

```text
客户端 ---> CheeseWAF 数据平面 ---> 源站
                 |
                 +-- 管理 API / Web 控制台 / waf-cli
                 +-- 日志 / 指标 / 安全报告
```

数据平面负责检测和转发流量。管理平面默认只监听本机，负责站点配置、规则、用户、日志和运行状态。

## 快速开始

### 使用 Docker Compose

```bash
git clone https://github.com/LaokeQwQ/CheeseWAF.git
cd CheeseWAF
docker compose -f deploy/docker/docker-compose.yml up -d --build
docker compose -f deploy/docker/docker-compose.yml logs -f cheesewaf
```

启动后访问：

- 管理向导：`https://127.0.0.1:9443/setup`
- 数据平面：`http://127.0.0.1:8080`

容器使用自签名管理证书。首次初始化令牌只会写入启动日志。完成初始化后，请先把示例站点的上游地址改成真实源站。

停止服务：

```bash
docker compose -f deploy/docker/docker-compose.yml down
```

数据保存在 Compose 命名卷中，执行 `down` 不会删除这些卷。

### 从源码运行

仓库当前使用 Go 1.26.5。Docker 构建使用 Node.js 24.18.0；本地构建 Web 控制台时建议使用相同的大版本。

```bash
git clone https://github.com/LaokeQwQ/CheeseWAF.git
cd CheeseWAF

cd web
npm ci
npm run build
cd ..

go run ./cmd/cheesewaf serve
```

本地默认管理地址是 `http://127.0.0.1:9443/setup`。首次启动会在 `data/` 中创建运行配置、数据库和证书目录。

## 配置

本地首次启动会生成 `data/cheesewaf.yaml`。仓库中的 [示例配置](configs/cheesewaf.yaml) 列出了主要配置项：

- `server`：数据平面和管理平面的监听地址与 TLS；
- `sites`：域名、源站、检测策略、访问控制和重写规则；
- `protection`：全局防护等级、IP、限流、Bot 和 API 安全策略；
- `storage`、`logging` 和 `monitor`：数据库、日志后端、指标与告警。

管理平面默认绑定 `127.0.0.1`。如需公开监听，必须同时启用 `server.admin_public` 和管理 TLS，并限制网络访问范围。

## 开发与验证

运行 Go 检查：

```bash
go test ./...
go vet ./...
```

运行 Web 检查：

```bash
cd web
npm ci
npm run typecheck
npm test
npm run build
```

运行内置语义样本：

```bash
go run ./cmd/cheesewaf-corpus --mode analyzer
```

也可以对已部署的数据平面回放样本：

```bash
go run ./cmd/cheesewaf-corpus \
  --mode http \
  --base-url http://127.0.0.1:8080
```

其他构建、测试和安全验证入口见 [Makefile](Makefile) 与 `scripts/ci/`。

## 项目结构

- `cmd/`：服务、语义样本工具和 Windows 控制器入口；
- `internal/`：代理、防护、管理 API、存储、集群和调度代码；
- `web/`：React 管理控制台；
- `configs/`：配置示例；
- `deploy/`：Docker、systemd 和 Windows 安装文件；
- `scripts/ci/`：构建、打包和发行验证脚本。

## 安全说明

- CheeseWAF 不能替代源站自身的身份认证、授权和输入校验。
- 默认 `smart` 策略偏向降低误报。生产部署前应使用真实业务流量和攻击样本调整策略。
- 内置样本用于回归验证，不代表已经达到 ModSecurity、Coraza 或 OWASP CRS 的等价覆盖。
- 请保护管理令牌、初始化令牌、私钥和日志。不要把这些内容提交到仓库。

## 许可证

CheeseWAF 使用 [Apache License 2.0](LICENSE)。
