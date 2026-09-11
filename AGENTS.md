# CheeseWAF 项目约束

这份文件是 CheeseWAF 源码、构建和交付的维护约束。任何代码、构建脚本或文档变更都必须保持这些边界。

## 生产构建边界

1. `@agent-eyes/agent-eyes`、code-inspector、`codex-acp` 以及依赖它们的布局检查脚本只能用于本地开发和测试；本地开发也必须显式设置 `CHEESEWAF_AGENT_EYES=1` 才能启用。
2. 它们不得进入生产 JavaScript、Go 发布包、Docker 运行时镜像、安装包、生产依赖清单或运行时配置。
3. 生产/发布构建必须设置 `CHEESEWAF_AGENT_EYES=0`，并使用 `npm ci --ignore-scripts`；不得执行该依赖的 monorepo `postinstall`。
4. Web 构建完成后必须执行产物检查，发现 `agent-eyes`、`code-inspector` 或 `codex-acp` 标记时构建失败。
5. 生产容器只复制 Web 静态产物和 Go 二进制，不复制 `node_modules`、测试工具、编辑器插件或 Agent 工具链。

## 配置与运行数据边界

- `configs/cheesewaf.yaml` 是版本控制中的模板，初始化和控制台写操作必须使用 `data/config/cheesewaf.yaml` 等运行时副本。
- 运行时数据库、密钥、证书、Token、日志和临时文件不得写入源码模板或提交到 Git。
- 管理平面默认保持 loopback 监听；任何远程暴露都必须同时说明 TLS、ACL、审计和回滚方式。
- 身份标识（管理员、操作者、租户和服务账号）必须使用严格的无空白格式；认证和审批核心不得用 `TrimSpace` 悄悄改写输入。UI 可以提示后让用户重新输入，服务端应拒绝前后空格、控制字符和不可见空白。

## 文档交付门禁

- README、CheeseSec_Docs 和发布说明中的命令、配置键、端口和初始化流程必须与当前代码和 UI 一起验收。
- 配置键发生变化时，必须同步中英文 README、线上手册源文件和迁移说明。
- 文档中的每条 Get Started 步骤都应能在干净工作区执行，且不得污染跟踪文件。
