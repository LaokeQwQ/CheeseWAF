<p align="center">
  <img src="web/public/cheesewaf-logo.png" alt="CheeseWAF 标志" width="128">
</p>

<h1 align="center">CheeseWAF</h1>

<p align="center">
  用 Go 写的自托管 Web 应用防火墙。<br>
  部署在客户端和源站之间，并提供同一套管理 API、Web 控制台和终端界面。
</p>

<p align="center">
  <a href="README.md">English</a> ·
  <a href="README_CN.md">简体中文</a> ·
  <a href="LICENSE">Apache-2.0</a>
</p>

> 还没正式对外。配置和接口仍可能改。先在受控环境里验证，再接到生产流量。

## 目录

- [它做什么](#它做什么)
- [怎么摆](#怎么摆)
- [防护等级](#防护等级)
- [快速开始](#快速开始)
- [配置](#配置)
- [开发](#开发)
- [目录结构](#目录结构)
- [文档](#文档)
- [对外发布前](#对外发布前)
- [许可证](#许可证)

## 它做什么

CheeseWAF 放在客户端和源站中间。数据面检查 HTTP 请求和响应。管理面默认只听本机，用来改站点、规则、用户、日志和运行状态。

- **Web 攻击。** 分阶段语义分析覆盖 SQL 注入、XSS、RCE、LFI、XXE、SSRF、NoSQL 注入、SSTI 等。支持自定义规则和可选的响应检查。
- **先压误报再拦。** 单个解码字段里几乎只有攻击内容（完整形状）从 2 档起可拦。夹在文章里的同样字节，2～4 档放行，只有 5 档当场拦。
- **待确认。** 没当场拦住的可疑请求，以及 5 档已经拦住的请求，都会进 `/review`。管理员可以加长期内容 / URL / IP / 客户端指纹拦截，或放行并加白名单。站点已有的模型在后台问，不挡住这次请求。
- **Bot 与流量。** 限流、JS 工作量证明、图片验证码、滑块验证码、排队室。
- **API 安全。** 请求结构校验、端点限流、JWT 校验（HMAC、PEM 或 JWKS）。
- **访问控制。** 全局、站点、路径级 IP 规则，信誉分，GeoIP，以及按供应商 CIDR 绑定的可信代理。
- **运维。** Web 控制台、REST API 和 `waf-cli` 共用一套数据。带 RBAC、可撤销会话、审计、Prometheus 指标和多种日志后端。
- **部署。** 提供 Docker Compose、systemd 和 Windows 打包。可选集群加入、证书轮换和滚动升级。

**不会**替代源站自己的登录和授权。  
**不会**给对方 CMS 删稿。  
**不会**用大模型当主检测器。

## 怎么摆

```text
客户端  --->  CheeseWAF 数据面  --->  源站
                    |
                    +-- 管理 API / Web 控制台 / waf-cli
                    +-- 日志 / 指标 / 报告
```

本地启动后的默认地址：

| 平面 | 地址 |
| --- | --- |
| 数据面 | `http://127.0.0.1:8080` |
| 管理（初始化） | `http://127.0.0.1:9443/setup`；Docker 里一般是 `https://127.0.0.1:9443/setup` |

## 防护等级

站点字段：`waf.paranoia_level`。新站默认 **3**。YAML 省略时按 3。写明 `0` 仍只记不拦。

| 档 | 完整形状 | 夹在文章里 |
| --- | --- | --- |
| 0～1 | 只记 | 只记 |
| 2～4 | 当场拦 | 放行，问模型，进待确认 |
| 5 | 当场拦 | 当场拦，仍问模型 |

4 档夹杂命中后，可用 `promote_seconds` 短时按 5 档拦。截止时间写入 SQLite，重启不丢。

一键指纹拦截用 `User-Agent` 加 `Accept-Language` 的 SHA-256 前 8 字节（16 位十六进制）。不是 JA3。

细则见 [docs/protection-policy-roadmap.md](docs/protection-policy-roadmap.md)。

## 快速开始

### 用 Docker Compose

```bash
git clone https://github.com/LaokeQwQ/CheeseWAF.git
cd CheeseWAF
docker compose -f deploy/docker/docker-compose.yml up -d --build
docker compose -f deploy/docker/docker-compose.yml logs -f cheesewaf
```

然后打开 `https://127.0.0.1:9443/setup`。容器用自签名管理证书。首次初始化令牌只写在启动日志里。初始化完成后，把示例站点的上游改成真实源站。

```bash
docker compose -f deploy/docker/docker-compose.yml down
```

数据在 Compose 命名卷里。执行 `down` 不会删这些卷。

### 从源码运行

需要 **Go 1.26.6** 和 **Node.js 24.18.0**（控制台用同一大版本即可）。

```bash
git clone https://github.com/LaokeQwQ/CheeseWAF.git
cd CheeseWAF

cd web
npm ci
npm run build
cd ..

go run ./cmd/cheesewaf serve
```

首次启动会在 `data/` 下创建运行配置、SQLite 和证书目录。打开 `http://127.0.0.1:9443/setup`。

## 配置

本地启动会写出 `data/cheesewaf.yaml`。仓库示例见 [configs/cheesewaf.yaml](configs/cheesewaf.yaml)。

| 段 | 用途 |
| --- | --- |
| `server` | 数据面和管理面的监听地址与 TLS |
| `sites` | 域名、源站、检测策略、白名单、重写 |
| `protection` | 全局等级、IP、限流、Bot、API 安全 |
| `storage` / `logging` / `monitor` | 数据库、日志后端、指标和告警 |
| `ai` | 可选。待确认和后台助手用站点已有模型 |

管理面默认绑定 `127.0.0.1`。要公开监听，必须同时打开 `server.admin_public` 和管理 TLS。

## 开发

```bash
go test ./cmd/... ./internal/...
go vet ./cmd/... ./internal/...

cd web
npm ci
npm run typecheck
npm test
npm run build
```

回放内置语义样本：

```bash
go run ./cmd/cheesewaf-corpus --mode analyzer
go run ./cmd/cheesewaf-corpus --mode http --base-url http://127.0.0.1:8080
```

合入路径：`feature/*` → `dev` → `canary` → `master`。必过检查绿了再合。

## 目录结构

| 路径 | 内容 |
| --- | --- |
| `cmd/` | 服务、语料回放、Windows 控制器 |
| `internal/` | 代理、检测、管理 API、存储、集群 |
| `web/` | React 管理控制台 |
| `configs/` | 示例 YAML |
| `deploy/` | Docker、systemd、Windows |
| `docs/` | 产品和引擎说明 |
| `scripts/ci/` | 构建、打包和 CI 脚本 |

## 文档

| 文档 | 内容 |
| --- | --- |
| [docs/protection-policy-roadmap.md](docs/protection-policy-roadmap.md) | 0～5 档、待确认、明确不做的事 |
| [docs/paranoia-level-implementation.md](docs/paranoia-level-implementation.md) | 档位如何接到代码 |
| [docs/performance-optimization.md](docs/performance-optimization.md) | 运行时和分析器说明 |

## 对外发布前

- 管理面走 TLS 或可信反向代理。不要在明文 HTTP 上暴露浏览器令牌。
- Prometheus 抓取默认不公开。优先用带认证的 `/api/metrics`。要公开时再设 `monitor.prometheus.public: true`。
- 打发行包前，对已部署的数据面和管理面跑 `cheesewaf-corpus --mode gate`。`--skip-external` 只给 CI 回放用，不能当发行证据。
- 默认 `smart` 策略偏向少误报。上线前用真实流量和自己的样本调。内置语料是回归用的，不表示已经和 ModSecurity、Coraza 或 OWASP CRS 等价。
- 城市级地图需要 GeoIP City 库或外部位置源。没有这些数据时，只做到国家 / CIDR，不会编造坐标。

## 许可证

[Apache License 2.0](LICENSE)。
