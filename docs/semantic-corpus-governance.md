# 语料治理与检测评估实施计划

本计划用于 CheeseWAF 语义检测器的语料接入、隔离区复核、误报控制和可复现实验。当前阶段先建立可审计的本地流水线，不自动下载外部数据，也不把来源不明或许可不清的样本放入正式训练集。

## 目标与硬约束

- 所有语料（现有和新增）在训练、调参或评估前，必须依次经过：全局去重、结构初筛、语义筛选、隐私/密钥清洗、来源与许可核验、分组切分。
- 隔离区样本只能在独立的二次语义复核通过后进入候选集；未复核、复核拒绝或证据不足的样本继续留在隔离区。
- 当前受治理回归快照的 `block + challenge` 请求级误报率必须低于 `0.8%`。在满足统计样本量和切片覆盖后，继续以更低的实测值为优化目标；独立盲测另行验收。
- 不能以静默跳过、缩小分母、删除修复样本或跨集合重复来制造更好的指标。
- 只接受公开且无需申请的来源；许可证、隐私和再分发条件不清的来源只能进入研究隔离区。需要申请、注册、API key、NDA 或授权确认的来源不进入正式候选池。
- 本分支保持工作区整洁：不覆盖输入文件，不提交生成的大型语料，所有生成物使用显式输出目录并可由 manifest 复核。

训练集按用途分层，不把不同粒度的数据混成一个 HTTP 金标准：请求级 HTTP/WAF 记录用于主训练与评估，PCAP/Zeek/流量日志用于外围行为和压力分析，payload、规则与模板样本用于检测器增强。每一层都必须与现有语料一起做全局去重、结构初筛、语义挑选、隐私/密钥清洗和许可核验；任何一层都不得绕过这条流水线直接进入训练或评估。切分时按站点、用户、会话和时间边界隔离，避免同源变体泄漏到不同集合。

## 实施顺序

### P0：基线与治理流水线

1. 固定分支基线、工具链、配置、输入文件 SHA-256 和清洗规则版本。
2. 增加本地语料治理器，支持规范 JSONL、原始 HTTP JSONL、压缩输入和 payload-only 记录。
3. 对所有输入执行全局精确去重和规范化指纹去重；重复记录保留来源、行号和频次关系，不静默丢失。
4. 执行结构初筛：编码、行长、请求方法/目标、Header、Body、标签、类别、解码深度和可适配性检查。
5. 执行语义初筛：类别证据一致性、占位符/模板、纯安全 prose、协议级样本与 HTTP 语义样本分层。
6. 执行 PII/密钥清洗和许可证登记；原始值不写入审计报告，必要时使用不可逆替换或 HMAC。
7. 将拒绝、待复核、修复、重复和证据不足记录写入原子生成、按哈希标识的隔离快照；生成包含输入/输出哈希、计数和规则版本的 manifest。历史快照由调用方归档，不在输入目录内追加写入。

### P1：隔离区二次复核与接线

1. 定义中性的复核接口和决定文件格式，复核结果必须绑定记录指纹、规则版本和复核人；可选记录 RFC3339 复核时间。
2. 只有 `approve` 且通过所有硬性安全检查的隔离样本才可生成 formal 候选集；复核文件缺失、复核人缺失、指纹不匹配或版本不一致时默认拒绝。
3. 将治理命令接入 `cmd/cheesewaf-corpus`、Makefile、GitHub Actions 和 Forgejo Actions；默认只读输入，输出到临时目录。
4. 评估器读取治理 manifest，报告正式集、隔离集、重复、修复、未知标签和不可适配样本，禁止静默改变分母。

### P2：检测质量、性能和安全边界

1. 用独立盲测集调节策略仲裁：高置信 sink 证据优先，弱上下文只能降低置信度或进入 challenge/log，不得抹除强证据。
2. 统一请求取消、CPU/内存/解压/Body/AST/队列预算，禁止超时后继续写结果或泄漏 worker/permit。
3. 使用按站点的不可变运行时快照、带策略版本的缓存和 singleflight，避免并发下规则漂移与缓存污染。
4. 通过硬负例、协议差分、变异攻击、线上回放和 FP/FN 台账逐类迭代；禁止把自动反馈直接回灌训练。

## 验收门禁

- 语料治理：输入和输出 SHA-256 可复现；重复关系、隔离原因、复核决定和清洗计数完整；无静默跳过。
- 质量：受治理回归快照的 `FPR(block + challenge) < 0.8%`，并报告 99% 单侧置信上界、来源/站点/时间/协议切片；TPR、未知标签和修复比例单独报告，独立盲测另行验收。
- 稳定性：`go test`、`go test -race`、fuzz、解析器差分、10k/100k 并发、慢速请求、压缩炸弹、超大请求和客户端断连测试通过。
- 工程：`gofmt`、`go vet`、lint、死代码/未使用符号检查通过；配置、命令、文档和测试均有实际引用。
- 发布：shadow → log-only → challenge → 小流量 block → 分站点扩大的灰度顺序；任何门禁回退自动停止扩大范围。

## 当前不纳入正式集的来源

需要申请、注册、API key、NDA、授权确认或许可证不清的外部数据，统一留在研究隔离区。PCAP、Zeek、URL-only、蜜罐和安全文章正文只能作为外围行为、协议压力或 hard-negative 参考，不能冒充完整 HTTP 请求级金标准。

## 外部源登记与证据

公开直下只表示访问门槛低，不等于允许商用或再分发。每个外部文件在进入候选池前都应有 sidecar 登记：数据集名、源 URL、精确版本/发布日期、文件 SHA-256、文件级许可证原文或证据快照、商用/再分发决定、署名要求、PII/凭据/恶意内容标记、粒度与 intended use、合成/真实标记、变换链、审批人和下次复核日期。任一证据缺失、链接失效或许可证变化时自动降级到 research quarantine；软件仓库的总 LICENSE 不能替代第三方数据文件的授权证据。

训练集比例只作为分层参考，不是可以相加的硬配方：白流量、已知攻击、变形攻击、真实恶意流和业务滥用分别报告来源与分母；未经验证的研究隔离样本不为满足比例而补入正式集。payload、规则或模板若要转成请求级样本，必须在隔离靶场中重放并记录方法、URI、Header/Cookie/Body、响应、类别、成功状态和生成器版本。

## 操作约定

- 仅在用户明确要求后下载或接入外部数据；本计划阶段不联网抓取、不覆盖现有语料。
- 生成物默认写入临时目录；正式候选集和 manifest 必须经过代码审查后再决定是否提交。
- 文档中的指标只代表带版本和哈希的具体快照，不把历史快照混称为当前基线。

## 当前命令与复核文件

治理命令只接受本地 JSON 配置，不会自行联网或下载数据。CI 会递归、稳定地
枚举 `testdata/` 下的 `.jsonl` 与 `.jsonl.gz`，并以仓库相对路径作为稳定来源名；
optional 判定对嵌套目录和 gzip 文件同样有效。配置中的
`sources`、`existing` 和 `incoming` 会在同一轮执行全局去重；大型或暂时
不可用的文件可声明为 `optional`，缺失路径会写入 manifest 的
`missing_optional`，而不是改变分母。

```json
{
  "pipeline_version": "corpus-governance-v1",
  "rule_version": "v1",
  "sources": [{
    "path": "/绝对路径/incoming.jsonl",
    "name": "incoming",
    "license": "MIT",
    "access": "public-direct",
    "allow_formal": true
  }],
  "review_path": "/绝对路径/reviews.jsonl",
  "formal_path": "/临时目录/formal.jsonl",
  "quarantine_path": "/临时目录/quarantine.jsonl",
  "manifest_path": "/临时目录/manifest.json"
}
```

复核文件按 JSONL 记录指纹和决定；`reviewer` 必填，规则版本必须与配置
一致。示例：

```json
{"fingerprint":"<sha256>","rule_version":"v1","decision":"approve","reviewer":"security-review","reviewed_at":"2026-08-31T00:00:00Z"}
```

本分支的 CI 治理检查将所有现存样本保持在隔离快照中（`allow_formal=false`），
只验证去重、初筛、清洗、计数和哈希完整性；它不会把未经人工复核的样本
自动变成正式评估集。

CI 另有一条受治理正式快照门禁。它仅以仓库内已整理的
`curated_external_shapes.jsonl`、`benign_production_shapes.jsonl` 和
`handcrafted_attack_neighbors.jsonl` 为输入，先生成带来源、指纹、原始行哈希和
manifest 输出哈希的 `formal.jsonl`，再让命令行回放器和评估器消费该快照。进入
治理流程后，检测侧不再直接读取这三份原始文件。门禁会核对正式集行数、输出
哈希、来源元数据、结构拒绝数和类别样本量；manifest 与快照不一致时直接失败。正式快照还固定三份输入的 SHA-256、来源/标签/类别精确计数，并要求 hard reject 为零，不能只保持总行数或比例而替换困难样本。规范 JSON 和原始 Header 块中的重复键/重复字段名也会被记录并隔离，禁止解析器静默覆盖输入。

正式快照同时钉死治理 pipeline、规则版本、策略哈希和 `formal.jsonl` 的完整 SHA-256；因此仅重算 manifest 或替换同数量样本不能绕过门禁。当前快照为
`14333` 行（benign `293`、attack `14040`），formal 输出哈希为
`5a5173d3d52067f10be2b18cbbcc1ee6dd8db1743ae277e71896ca3c1549af75`，策略哈希为
`f7a14247f037ad6e984eb08abc0189a6f05a6c8850747717b68903cce9d7731a`。这些数值只
描述本分支这一个版本化回归快照，不替代独立盲测。

`quarantine_malformed_samples.jsonl` 保留了原始的 `pat-sqli-00119` 畸形记录（含
控制字节/替换字符）作为隔离证据；该行因结构与来源门禁失败而明确不进入 formal，
也没有被改写成更容易检出的替代样本。门禁会同时钉住隔离文件和该行的 SHA-256，
防止通过静默删除、替换或缩小 attack 分母来改善指标。只有完成独立二次复核并更新
审计记录后，才可讨论是否重新纳入候选集。

当前 CI 要求正式快照至少包含 250 条 benign 和 10,000 条 attack，且
`FPR < 0.8%`、`TPR >= 99%`。这是对当前仓库内受治理回归快照的质量门禁，不等同于
独立盲测结论，也不代表所有研究隔离语料已经达到同一指标。

`aetherguard_undetectable.jsonl` 是攻击研究隔离源：名称表示当前检测能力不覆盖
其类别，不代表 benign。CI 强制将其声明为 `default_truth=attack`、
`access=research-quarantine`、`allow_formal=false`；它参与完整性与研究统计，但
不能自动进入正式集。

### CI 质量预算

下列非负整数环境变量可由调用方显式覆写；CI 配置固定写出当前预算，后续只应
在清洗后收紧，扩大 optional 本地语料时若需放宽必须留下审计理由：

| 变量 | 当前 CI 值 | 口径 |
|---|---:|---|
| `CORPUS_GOVERNANCE_MAX_PARSE_ERRORS` | 0 | 无法解析/适配为支持记录格式的行 |
| `CORPUS_GOVERNANCE_MAX_INVALID_UTF8` | 0 | 非法 UTF-8 行 |
| `CORPUS_GOVERNANCE_MAX_OVERLONG` | 0 | 超过治理读取上限的行 |
| `CORPUS_GOVERNANCE_MAX_LABEL_CONFLICTS` | 3 | `by_reason.label_conflict` 行级原因计数 |
| `CORPUS_GOVERNANCE_MAX_REPAIRS` | 127 | 适配器修复或丢弃畸形 Header 行后的 canonical 行数 |

任一 required 来源产出 0 条 classified 记录（空文件，或整源全部拒绝/不可适配）
也会直接失败，不受预算豁免。

### quarantine 行数口径

`quarantine.jsonl` 同时包含三类记录，CI 会逐行解析并与 manifest 对账：

- `canonical = manifest.quarantine - manifest.duplicates`：去重后仍留在隔离区的代表行；
- `duplicate = manifest.duplicates`：带 `duplicate_exact` 或
  `duplicate_semantic` 原因的重复行；
- `rejected = counts.parse_error + counts.invalid_utf8 + manifest.overlong`：
  `kind=rejected_record` 的结构拒绝行。

因此 artifact 总行数为 `manifest.quarantine + rejected`；重复行已包含在
`manifest.quarantine` 内，不能再额外相加。

### 本地门禁命令

```bash
# 审计 testdata 下全部现有语料；所有记录保持在隔离快照中
make corpus-governance

# 生成受治理正式快照，并执行回放与评估门禁
make security-corpus
```

## 当前里程碑状态

- 已接线：本地治理核心、规范/原始/payload-only/压缩输入、全局去重、初筛与脱敏、隔离快照、复核决定、输入/解压/记录资源预算、CLI、Makefile、两套 CI、严格百分比门禁解析。
- 已接线：受治理正式快照的哈希与行数校验、命令行回放、评估器替换数据源、最小类别样本量检查，以及当前回归快照的 `FPR < 0.8%` / `TPR >= 99%` 门禁。
- 已验证：现有全部本地语料的输入/输出哈希、重复关系、逐行计数守恒和缺失 optional 路径；受治理正式快照已同时接入回放器与评估器。
- 已验证：RCE 正则族接入必要标记门控，原始控制字符与 NFKC 规范化视图并行保留；Unicode 折叠、宽字符分隔符、换行链和执行参数中的裸命令均有回归覆盖。对 5,000 条长 benign 导出样本，RCE 慢路径耗时约下降 28%，攻击样本门控差分未发现漏检。
- 后续里程碑：独立盲测快照、按来源/时间/站点分组切分、置信上界报告、运行时并发与资源压力测试、持续性能基准。未完成项不作为当前能力宣称。
