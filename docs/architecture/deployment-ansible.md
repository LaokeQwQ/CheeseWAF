# Ansible 商业部署边界

deploy/ansible 提供 CheeseWAF 的主机准备、外部依赖交接和 CWEDP 引导边界。它不把
Pigsty 源码、插件包或运行时密钥放进仓库，也不把当前尚未接通的生产控制面伪装成已可用。

## 入口和存储模式

| 入口 | 固定 profile | 用途 | 额外 PostgreSQL/Redis |
| --- | --- | --- | --- |
| single-node.yml | temporary | 单节点临时运行时或主机准备 | 不启动、不安装、不探测 |
| production.yml | production | 已有外部依赖的生产交接 | 必须显式提供外部 PG、外部 Redis、native-raft |
| full.yml | production | 生产交接加可选 Pigsty 适配器和 CWEDP 引导 | 只调用外部适配器，不携带其源码 |

入口中的 vars 是硬边界；例如给 single-node.yml 传入
cheesewaf_storage_profile=production 会失败。生产 profile 还必须传
cheesewaf_provision_only=true 才会进入基础设施交接阶段。原因是当前 CheeseWAF 启动路径
仍会以 ErrProductionStorageUnavailable 拒绝未接通的 PostgreSQL/Coordinator/native-raft
一体化启动单元。完成真实运行时接线、迁移、健康探针和回滚演练后，才可以移除该交接门禁。

生产必填变量来自外部 secret 机制（Ansible Vault、控制器密钥服务或 CI secret），本仓库只保留
空默认值：

- cheesewaf_management_postgresql_mode=external
- cheesewaf_management_postgresql_dsn，必须使用 sslmode=verify-full
- cheesewaf_redis_mode=external、cheesewaf_redis_address、cheesewaf_redis_tls_enabled=true
- cheesewaf_redis_ca_file
- cheesewaf_consensus_backend=native-raft、cheesewaf_native_raft_endpoints（全部 HTTPS）
- cheesewaf_native_raft_ca_file 和严格的 cheesewaf_cluster_id

外部 PG 是管理面持久真相；native-raft 保存成员、term、epoch、fencing 和期望状态顺序；
Redis 只承载租约、锁、缓存和短期安全状态。Ansible 不会启动本地 PG/Redis，也不会把管理 PG
DSN 写入 deployment-contract.yml。

## Pigsty 适配器

full.yml 的 Pigsty 入口只接受控制器本地、人工审核的适配器 checkout：

1. cheesewaf_pigsty_version 是固定的 MAJOR.MINOR.PATCH 版本字符串。
2. cheesewaf_pigsty_ref 必须是 checkout 的 40 位 Git commit；任务会检查 HEAD、干净工作区和
   tracked regular file。
3. cheesewaf_pigsty_checkout、cheesewaf_pigsty_inventory、cheesewaf_pigsty_vars_file
   必须是控制器上的绝对路径。vars_file 放在仓库外，并可由 Vault 解密后临时提供。
4. 适配器由控制器当前 Ansible Python 解释器调用一次；Ansible 不 clone、get_url、解压或
   更新 Pigsty。适配器自己必须声明并实现 cheesewaf_offline、版本和 commit 约束。

默认 cheesewaf_offline=true。离线时适配器不得访问仓库、软件源、镜像仓库或外部 API；需要
联网时必须由操作者显式传入 cheesewaf_offline=false，并在适配器自身建立审计过的 allowlist。
--check 只验证本地 checkout 和输入文件，不执行适配器，因此不会改变数据库或主机。

## CWEDP 与插件边界

插件和 CRP 包只能由 CWEDP 根据签名 DistributionIntent、节点 HELLO/CAPABILITIES 和
来源登记完成自协商分发。cheesewaf_plugin_push、cheesewaf_crp_push 以及包列表变量会
直接失败；剧本没有插件上传、安装、升级或回滚任务。

CWEDP 代理必须由操作者提供本地二进制和 SHA-256：

    cheesewaf_cwedp_agent_enabled=true
    cheesewaf_cwedp_agent_src=/secure/staging/cwedp-agent
    cheesewaf_cwedp_agent_sha256=<64 hex characters>

Ansible 按摘要建立不可变 releases/<sha>/ 目录和 current 链接，只安装带
--pull-only 参数的 systemd 单元。启动代理还需显式设置
cheesewaf_cwedp_agent_start=true，并提供仓库外、权限为 0600 或 0640 的
cheesewaf_cwedp_environment_file；令牌、证书和私钥始终由外部机制管理。换版本时保留旧
release 目录，回滚只需把 current 指向已审核的旧摘要并重新加载单元，回滚事件应由控制面
审计。

## 主机安全、TLS、ACL 和回滚

管理平面默认监听 127.0.0.1:9443。改为远程地址时，预检会同时要求：

- cheesewaf_management_tls_enabled=true；
- 非空 cheesewaf_management_acl，由外部防火墙/反向代理和主机 ACL 共同收敛；
- cheesewaf_management_audit_sink 可审计地址；
- cheesewaf_management_rollback_ref 指向 last-known-good 控制面版本。

剧本只写入非敏感的部署合同和 systemd 单元；不会把 DSN、Redis 密码、Vault 内容、证书、私钥、
临时 token 或日志写回模板、Git 跟踪文件或 Ansible 输出。所有涉及密钥值的断言和命令均使用
no_log。

## 幂等和离线验收

预检任务无副作用，可直接 --check。主机变更任务在 check-mode 下整体跳过并打印计划，避免
在不具备目标用户或 systemd 的控制器上制造假变更；普通运行使用 Ansible 模块的状态收敛，
release 目录按摘要寻址，合同文件按内容更新，重复执行不会下载或复制未变化的工件。

在不安装任何依赖时运行静态合同检查：

    deploy/ansible/verify-offline.sh --static-only

在具备已批准的 ansible-core（以及可选 ansible-lint）时运行完整离线验证：

    ANSIBLE_PLAYBOOK=/path/to/ansible-playbook deploy/ansible/verify-offline.sh

脚本会执行三个入口的 syntax-check、single-node 无服务检查、生产依赖缺失/安全条件拒绝、
production/full provision-only 预检、插件推送拒绝、远程管理 TLS/ACL/审计/回滚门禁和浮动
Pigsty ref 拒绝。它不会连接数据库、Redis、Pigsty、软件源或 systemd。实际生产执行前仍需
在隔离环境用 --check，再由变更审批放行一次明确的 provision-only 运行。
