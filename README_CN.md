<p align="center">
  <img src="web/public/cheesewaf-logo.png" alt="CheeseWAF 标志" width="128">
</p>

<h1 align="center">CheeseWAF</h1>

<p align="center"><em>奶酪有洞，AI 来控。</em></p>

<p align="center">
  <strong>ALAP</strong> · AI Large-Language-Model Auto Pilot<br>
  由大语言模型驱动的新一代自托管 WAF。<br>
  WEB + 控制面板 + CLI。源站还在你手里。
</p>

<p align="center">
  <a href="README.md">English</a> ·
  <a href="README_CN.md">简体中文</a>
</p>

<p align="center">
  <a href="LICENSE">Apache-2.0</a>
</p>

<p align="center">
  <a href="https://github.com/LaokeQwQ/CheeseWAF/stargazers"><img src="https://img.shields.io/github/stars/LaokeQwQ/CheeseWAF?style=flat-square&color=f5c542" alt="Stars"></a>
  <a href="https://github.com/LaokeQwQ/CheeseWAF/network/members"><img src="https://img.shields.io/github/forks/LaokeQwQ/CheeseWAF?style=flat-square" alt="Forks"></a>
  <a href="https://github.com/LaokeQwQ/CheeseWAF/watchers"><img src="https://img.shields.io/github/watchers/LaokeQwQ/CheeseWAF?style=flat-square" alt="Watchers"></a>
  <a href="https://github.com/LaokeQwQ/CheeseWAF/issues"><img src="https://img.shields.io/github/issues/LaokeQwQ/CheeseWAF?style=flat-square" alt="Issues"></a>
  <a href="https://github.com/LaokeQwQ/CheeseWAF/pulls"><img src="https://img.shields.io/github/issues-pr/LaokeQwQ/CheeseWAF?style=flat-square" alt="Pull requests"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/LaokeQwQ/CheeseWAF?style=flat-square" alt="License"></a>
  <br>
  <a href="go.mod"><img src="https://img.shields.io/github/go-mod/go-version/LaokeQwQ/CheeseWAF?style=flat-square&label=Go" alt="Go version"></a>
  <a href="https://github.com/LaokeQwQ/CheeseWAF/releases"><img src="https://img.shields.io/github/v/release/LaokeQwQ/CheeseWAF?include_prereleases&style=flat-square" alt="Release"></a>
  <a href="https://github.com/LaokeQwQ/CheeseWAF/commits"><img src="https://img.shields.io/github/last-commit/LaokeQwQ/CheeseWAF?style=flat-square" alt="Last commit"></a>
  <a href="https://github.com/LaokeQwQ/CheeseWAF/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/LaokeQwQ/CheeseWAF/ci.yml?branch=master&style=flat-square&label=CI" alt="CI"></a>
  <img src="https://img.shields.io/github/repo-size/LaokeQwQ/CheeseWAF?style=flat-square" alt="Repo size">
  <img src="https://img.shields.io/github/languages/top/LaokeQwQ/CheeseWAF?style=flat-square" alt="Top language">
  <img src="https://img.shields.io/github/languages/count/LaokeQwQ/CheeseWAF?style=flat-square" alt="Languages">
</p>

> 还没正式对外。CheeseWAF 是 **ALAP**（AI Large-Language-Model Auto Pilot）型 WAF：数据面先当场判定，站点里配置的大模型再接管待确认、自动同意和长期规则。配置和接口仍可能改。

## Menu

- [什么是 ALAP](#什么是-alap)
- [WEB + 控制面板 + CLI](#web--控制面板--cli)
- [流量路径](#流量路径)
- [防护等级](#防护等级)
- [安装](#安装)
- [配置](#配置)
- [技术栈](#技术栈)
- [开发](#开发)
- [文档](#文档)
- [许可证](#许可证)

## 什么是 ALAP

**ALAP** 是 **AI Large-Language-Model Auto Pilot** 的缩写。

中文叫「大语言模型自动驾驶」。

| 字母 | 原文 | 中文 |
| --- | --- | --- |
| **A** / **L** | AI Large-Language-Model | 大语言模型 |
| **A** **P** | Auto Pilot | 自动驾驶 |

一线检测仍是语义引擎，当场判定。模型在后台开车：写结论、建议处置、按你的开关自动同意。模型地址你自己配，不写死供应商。

### 为什么这样设计

普通 WAF 命中一条规则就结束了。CheeseWAF 把这次命中当成自动驾驶的起点。

1. 分阶段语义引擎看的是**单个解码后的字段**，不是整段 HTTP。
2. 完整形状（几乎只有攻击内容，薄包装如 `@`、末尾 `;`、`/{${...}}`）从 2 档起可拦。
3. 同样字节夹在文章里，2～4 档放行，只有 5 档当场拦。
4. 可疑请求仍进待确认。站点自己的模型在后台写结论，不挡住这次请求。
5. 管理员点一下，或打开自动同意，就会写成长期的内容、URL、IP 或指纹规则。

## WEB + 控制面板 + CLI

一套管理 API，三扇门。

| 入口 | 做什么 |
| --- | --- |
| **WEB** | 浏览器打开。电脑和手机是同一套界面。 |
| **控制面板** | 站点、规则、待确认、日志、地图、集群。日常就在这里点。 |
| **CLI** | 发行包里的 `waf-cli`（转到 `./cheesewaf cli`） |

三处共用 RBAC、可撤销会话和审计。

## 流量路径

每个请求走下面这条路。虚线是 ALAP，发生在响应已经出门之后。

```mermaid
flowchart TB
  C[客户端] --> L[监听 HTTP / TLS / HTTP3]
  L --> IP{IP / 地理 / 指纹拦截}
  IP -->|拦| BP[拦截页]
  IP -->|过| BOT{Bot / 限流 / 排队室}
  BOT -->|挑战| CH[验证码或排队]
  CH -->|通过| SEM
  BOT -->|过| SEM[语义分析]
  SEM --> SHAPE{完整形状还是夹杂}
  SHAPE -->|完整形状 2～5 档| BP
  SHAPE -->|夹杂 5 档| BP
  SHAPE -->|夹杂 2～4 档| PASS[放行并写入待确认]
  SHAPE -->|干净| ORIGIN[源站]
  PASS --> ORIGIN
  PASS -.-> ALAP[ALAP 队列]
  SEM -.->|5 档拦住仍问模型| ALAP
  ALAP --> LLM[站点配置的模型]
  LLM --> DEC{人工一键或自动同意}
  DEC --> RULE[长期内容 / URL / IP / 指纹]
  RULE --> IP
```

本地启动后的默认地址：

| 平面 | 地址 |
| --- | --- |
| 数据面 | `http://127.0.0.1:8080` |
| 管理初始化 | `http://127.0.0.1:9443/setup`；Docker 里一般是 `https://127.0.0.1:9443/setup` |

## 防护等级

站点字段：`waf.paranoia_level`。新站默认 **3**。YAML 省略时按 3。写明 `0` 仍只记不拦。

| 档 | 完整形状 | 夹在文章里 |
| --- | --- | --- |
| 0～1 | 只记 | 只记 |
| 2～4 | 当场拦 | 放行，问模型，进待确认 |
| 5 | 当场拦 | 当场拦，仍问模型 |

4 档夹杂命中后，可用 `promote_seconds` 短时按 5 档拦。截止时间写在 SQLite，重启不丢。

5 档已经拦住的条目，仍可加长期内容、URL、IP、指纹拦截。不能改成放行。

一键指纹用 `User-Agent` 加 `Accept-Language` 的 SHA-256 前 8 字节（16 位十六进制）。不是 JA3。

细则见 [docs/protection-policy-roadmap.md](docs/protection-policy-roadmap.md)。

## 安装

**优先用发行包 + systemd。** Compose 是一键拉起整套实例的备选。多机用控制台生成的 Ansible 剧本。

### 1. 发行包和 systemd（推荐）

`dev`、`canary`、`master` 推送后，CI 会打渠道包：

`cheesewaf-<version>-<os>-<arch>.tar.gz`

包里是一个目录：`cheesewaf`、`waf-cli`、内嵌的 `web/dist`、示例 `configs/`、`VERSION`。

```bash
tar -xzf cheesewaf-*-linux-amd64.tar.gz
cd cheesewaf-*

sudo install -m 0755 cheesewaf /usr/local/bin/cheesewaf
sudo ln -sf /usr/local/bin/cheesewaf /usr/local/bin/waf-cli

sudo mkdir -p /etc/cheesewaf /var/lib/cheesewaf /var/log/cheesewaf
sudo cp configs/cheesewaf.yaml /etc/cheesewaf/cheesewaf.yaml
sudo cp deploy/systemd/cheesewaf.service /etc/systemd/system/cheesewaf.service

sudo useradd --system --home /var/lib/cheesewaf --shell /usr/sbin/nologin cheesewaf
sudo chown -R cheesewaf:cheesewaf /etc/cheesewaf /var/lib/cheesewaf /var/log/cheesewaf

sudo systemctl daemon-reload
sudo systemctl enable --now cheesewaf
```

单元文件在 [deploy/systemd/cheesewaf.service](deploy/systemd/cheesewaf.service)，启动命令是：

```text
/usr/local/bin/cheesewaf serve --config /etc/cheesewaf/cheesewaf.yaml
```

然后打开初始化向导，建第一个管理员，把示例站点的上游改成真实源站。

Windows 可用 zip（`cheesewaf.exe serve`）或 NSIS 安装包。说明在 `deploy/windows/README.md`（打包备忘，默认不进 Git）。

注意：发行 tar 里不一定带 `deploy/systemd/`。可从本仓库拷这份 unit，或按上面的 `ExecStart` 自己写一份。

### 2. Docker Compose（备选，一键拉起）

适合先起一套完整实例，不是默认的生产形态。

```bash
git clone https://github.com/LaokeQwQ/CheeseWAF.git
cd CheeseWAF
docker compose -f deploy/docker/docker-compose.yml up -d --build
docker compose -f deploy/docker/docker-compose.yml logs -f cheesewaf
```

打开 `https://127.0.0.1:9443/setup`。镜像用自签名管理证书。首次令牌只出现在启动日志。

```bash
docker compose -f deploy/docker/docker-compose.yml down
```

数据在 Compose 命名卷里。执行 `down` 不会删卷。

### 3. 多机 Ansible

仓库里没有现成的 `deploy/ansible/` 目录。管理面按集群计划**生成**剧本：

`POST /api/cluster/deploy/ansible`

压缩包里有 `inventory.ini`、`playbook.yml`、systemd 角色和配置模板。里面没有 SSH 密码，也没有加入令牌。SSH 用你自己的 inventory 或 agent：

```bash
ansible-playbook -i inventory.ini playbook.yml
```

这套剧本里两台 WAF 是负载分担，还不是完整高可用。

### 从源码跑（开发用）

需要 **Go 1.26.6** 和 **Node.js 24.18.0**。

```bash
git clone https://github.com/LaokeQwQ/CheeseWAF.git
cd CheeseWAF
cd web && npm ci && npm run build && cd ..
go run ./cmd/cheesewaf serve
```

## 配置

首次启动会写出 `data/cheesewaf.yaml`。示例见 [configs/cheesewaf.yaml](configs/cheesewaf.yaml)。

| 段 | 用途 |
| --- | --- |
| `server` | 数据面和管理面的监听地址与 TLS |
| `sites` | 域名、源站、检测策略、白名单、重写 |
| `protection` | 全局等级、IP、限流、Bot、API 安全 |
| `storage` / `logging` / `monitor` | 数据库、日志后端、指标和告警 |
| `ai` | 站点模型。ALAP 待确认、自动同意和控制台助手都用它 |

管理面默认绑定 `127.0.0.1`。要公开听，必须同时打开 `server.admin_public` 和管理 TLS。

## 技术栈

| 层 | 选型 |
| --- | --- |
| 数据面 | Go 1.26、`chi`、YAML v3、quic-go（HTTP/3） |
| 检测 | 进程内分阶段语义分析、自定义规则 |
| ALAP | 站点自己配的对话接口（completions 或 messages 风格），异步待确认队列 |
| 存储 | 默认 SQLite（`modernc.org/sqlite`），日志可接到 PostgreSQL 等 |
| 管理 API | 同一二进制、Bearer 会话、RBAC |
| Web / 手机 | React 18、TypeScript、Vite、Tailwind、shadcn/Radix、TanStack Query |
| 终端 | Cobra + Bubble Tea（`waf-cli`） |
| 交付 | 单文件静态二进制、systemd、Docker、Windows zip / NSIS、生成式 Ansible |

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

回放内置样本：

```bash
go run ./cmd/cheesewaf-corpus --mode analyzer
go run ./cmd/cheesewaf-corpus --mode http --base-url http://127.0.0.1:8080
```

合入路径：`feature/*` → `dev` → `canary` → `master`。必过检查绿了再合。

## 文档

| 文档 | 内容 |
| --- | --- |
| [docs/protection-policy-roadmap.md](docs/protection-policy-roadmap.md) | 0～5 档、待确认、明确不做的事 |
| [docs/paranoia-level-implementation.md](docs/paranoia-level-implementation.md) | 档位如何接到代码 |
| [docs/performance-optimization.md](docs/performance-optimization.md) | 运行时和分析器说明 |

## 许可证

[Apache License 2.0](LICENSE)。
