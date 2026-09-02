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

对公开真实流量中出现的 Sentry 遥测 DSN，治理器仅匹配窄格式
`https://<key>@o<id>.ingest.<region>.sentry.io/<project>`；命中后沿用
`secret_detected` 硬隔离语义，并在输出中只保留 ingest 主机和项目路径、将 DSN
公钥替换为 `[REDACTED]`。普通 URL、域名或短标识不因包含相似片段而被拦截。

对 `http://`/`https://` authority 中明确出现的 `user:password@host` userinfo，治理器同样执行窄范围硬隔离，并在隔离快照中仅保留主机、将 userinfo 替换为 `[REDACTED]`。该规则只作用于 URI authority：路径中的冒号、普通 URL、邮箱地址不会因此触发。公开请求 Header 中的 `X-XSRF-Token`、`X-SF-CSRF-Token` 以及常见 `X-CSRF-Token`/`XSRF-Token`/`CSRF-Token` 视为凭据字段，命中后从隔离输出移除；普通自定义 Header 仍保留。

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

仓库中已经提交的外部公开回归夹具也统一视为 `research-quarantine`：它们可用于完整性检查、缺陷定位和 opt-in 研究统计，但不得作为独立 blind、独立 FPR/TPR 或质量门禁证据。文件可见、已清洗或已提交并不等于完成文件级许可、标签保真度和独立性复核；在 sidecar、版本、来源哈希和二次复核齐全前，不得因样本已存在于 `testdata/` 就把它移入 `formal` 或 `blind`。

## 外部源登记与证据

开放来源按粒度、访问门槛和许可证证据分层登记，候选入口与排除项见
[开放语料与日志目录](open-corpus-catalog.md)。目录只记录可审计的公开或本地
生成候选，不执行下载，也不把代码仓库的总 LICENSE 当作数据文件授权。

公开直下只表示访问门槛低，不等于允许商用或再分发。每个外部文件在进入候选池前都应有 sidecar 登记：数据集名、源 URL、精确版本/发布日期、文件 SHA-256、文件级许可证原文或证据快照、商用/再分发决定、署名要求、PII/凭据/恶意内容标记、粒度与 intended use、合成/真实标记、变换链、审批人和下次复核日期。任一证据缺失、链接失效或许可证变化时自动降级到 research quarantine；软件仓库的总 LICENSE 不能替代第三方数据文件的授权证据。

训练集比例只作为分层参考，不是可以相加的硬配方：白流量、已知攻击、变形攻击、真实恶意流和业务滥用分别报告来源与分母；未经验证的研究隔离样本不为满足比例而补入正式集。payload、规则或模板若要转成请求级样本，必须在隔离靶场中重放并记录方法、URI、Header/Cookie/Body、响应、类别、成功状态和生成器版本。

## 操作约定

- 仅在用户明确要求后下载或接入外部数据；本计划阶段不联网抓取、不覆盖现有语料。
- 生成物默认写入临时目录或已忽略的输出目录；显式设置 benchmark/评估报告路径时也应使用 `/tmp` 等临时位置，避免把报告、失败转储或原始流意外写入仓库。正式候选集和 manifest 必须经过代码审查后再决定是否提交。
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

本分支的 CI 治理完整性检查（`run-corpus-governance.sh`）将递归发现的现存样本
保持在隔离快照中（该审计配置统一使用 `allow_formal=false`），只验证去重、初筛、
清洗、计数和哈希完整性；它不会把未经人工复核的样本自动变成正式评估集。
正式门禁（`run-governed-semantic-gate.sh`）是独立的受治理回放流程，只消费下述
三份已审阅输入并显式生成、校验哈希绑定的 formal 快照；两条流程的分母和用途不混用。

CI 另有一条受治理正式快照门禁。它仅以仓库内已整理的
`curated_external_shapes.jsonl`、`benign_production_shapes.jsonl` 和
`handcrafted_attack_neighbors.jsonl` 为输入，先生成带来源、指纹、原始行哈希和
manifest 输出哈希的 `formal.jsonl`，再让命令行回放器和评估器消费该快照。进入
治理流程后，检测侧不再直接读取这三份原始文件。门禁会核对正式集行数、输出
哈希、来源元数据、结构拒绝数和类别样本量；manifest 与快照不一致时直接失败。正式快照还固定三份输入的 SHA-256、来源/标签/类别精确计数，并要求 hard reject 为零，不能只保持总行数或比例而替换困难样本。规范 JSON 和原始 Header 块中的重复键/重复字段名也会被记录并隔离，禁止解析器静默覆盖输入。

回放器还要求 `input_hashes` 非空、每个值为规范小写 SHA-256，并逐一覆盖
`source_specs` 中的必需与已存在 optional 源；只有 manifest 的
`missing_optional` 明确列出的缺失 optional 源可以没有输入哈希，未知或多余的路径会直接拒绝。
治理配置的 `sources`、`existing`、`incoming` 会先合并检查，空路径以及同一文件的
重复、大小写别名或符号链接别名都会在读取前拒绝；生成的 `source_specs` 也必须
逐路径唯一，避免同一文件以不同来源元数据重复计数。
这一步验证的是清单声明的完整性与自洽性；生成 split 时还会在有限资源预算内重新读取
每个仍存在的 `source_specs` 文件并比对原始字节哈希，同时拒绝 provenance 指向未声明
文件或治理后重新出现的 optional 源。回放还按文件系统身份拒绝 `source_specs` 的相对、
绝对和符号链接别名，并要求 `input_hashes`、`missing_optional` 使用声明中的精确路径，
避免同一文件被计作多个独立来源。`evaluate-split` 回放则只信任已锁定 artifact，
不会重新读取原始 source；发布时仍需把正式 artifact、manifest 和独立锁保存到受控位置，
不能把同一可写目录中的 manifest 自哈希当作源文件真实性证明。

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
- 已接线：按来源/站点/会话/请求指纹的分组切分、时间边界拒绝跨组泄漏、`train`/`validation`/`blind` artifact 校验、完整 assigned records 摘要、manifest/formal/split-input 双快照哈希绑定、split 创建时的 source 全量哈希与 provenance 路径归属核验、metadata envelope 与 formal 集合的一一成员核验、全部 governed 回放的外部 artifact SHA-256 强制校验、盲测入口的类别/独立组形状门禁，以及 99% Wilson 不确定性字段。内部 records 摘要用于发现意外修改，正式 artifact 哈希必须另存于独立发布记录或不可变元数据；sidecar 分组字段的生成与首次哈希捕获属于可信边界。分割修复只用于小型 smoke artifact，并显式记录 `repaired`，不作为独立证据。
- 已修复：`split --allow-ungoverned` 现在允许真正无 provenance 的手写 smoke 行，但只要输入携带任一治理 provenance 字段，就会逐行重读来源并核对 `raw_hash`、`fingerprint`、路径和行号；伪造字段不能再被 `evaluationRecordsGoverned` 误判为已治理。新增 CLI 回归覆盖伪造哈希、伪造路径和纯手写兼容路径。
- 已接线：`evaluation-lock` 首次捕获脚本。它先用完整 artifact/manifest 哈希和 CLI 回放校验，再生成不含请求体、Header、目标、原始路径或逐行结果的聚合锁；锁文件不可覆盖，报告中的 manifest/input/partition 摘要必须与 artifact 绑定一致，盲分区若被修复、缺少 benign/attack 或独立组不足则拒绝。锁文件只能复制到独立受控存储，不能把同一可写目录视为信任根。
- 已修复：评估制品锁定脚本不再在最终路径校验前解析符号链接；artifact、manifest 以及输出父目录的末级链接现在都会被拒绝，避免链接目标绕过受控目录与不可覆盖检查。新增集成回归连续运行通过。
- 已修复：split 与 evaluate-split 的本地输入现在通过 `Lstat → Open → SameFile` 身份链打开；治理分割、正式快照回放和评估制品回放均拒绝末级符号链接及打开期间的路径替换，且不改变既有 artifact 哈希语义。
- 已修复：治理核心读取语料源和复核文件时也通过 `Lstat → Open → SameFile` 固定文件身份；单独声明的末级符号链接、非普通文件或打开期间替换会在解析/哈希前失败，不再让链接目标绕过来源审计。
- 已修复：评估分割库在按行重建治理 provenance 索引时同样拒绝末级符号链接和非普通文件；直接调用 `ForEachEvaluationJSONL` 的使用方不会因绕过 CLI 的完整源哈希阶段而跟随别名文件，新增符号链接回归并通过竞态测试。
- 已修复：普通 analyzer/http/gate 回放入口的 `--corpus` 也统一通过 `Lstat → Open → SameFile` 打开，旧入口不再因末级符号链接绕过文件身份校验；新增 CLI 回归覆盖。
- 已修复：治理 manifest 的完整来源哈希校验不再先用 `Stat` 跟随单独声明的末级符号链接；哈希前后统一固定普通文件身份，并覆盖单源符号链接回归。
- 已接线：固定 4 条良性与 4 条攻击请求的语义 request-path 基准，覆盖顺序与并发运行并报告 `ns/op`、`B/op`、`allocs/op`；正式趋势仍需在固定机器和负载条件下持续采样。
- 已接线：结构化性能采样脚本 `scripts/ci/run-semantic-benchmark.sh` 及 `make semantic-bench-report`。两套 CI 在 Go 质量阶段记录固定工作负载的原始输出哈希、代码修订/脏状态、Go/系统环境，以及有界的 runner 类别、镜像/版本和标签摘要，并按 `GOMAXPROCS` 分组记录顺序/并行样本和中位数/p95；报告先写入临时路径，再以带运行号和提交号的短期 artifact 保存，便于跨运行趋势审计。缺样本或多样本直接失败，不设绝对阈值，也不把不同机器的数字混作发布结论；artifact 只用于趋势，不改变质量门禁。
- 已验证：提交 `25ee208fda7bd0f446346d8bebb8fd632f3348ae` 的干净工作区结构化基准（`benchtime=1s`、`count=3`、`GOMAXPROCS=1,4`、Go `1.26.6`、Darwin arm64）报告文件 SHA-256 为 `ee41413289d39566c0fee3dc4cccb9d25ae188b293b67d5df56472320bff6f4e`，原始输出 SHA-256 为 `fe2faaf8cc8e180a85b60f152fabff48f24248b43d0cde6efae3112d045b5830`；CPU1 顺序/并行中位数为 `10492/10046 ns/op`，CPU4 顺序/并行为 `8924/4212 ns/op`，分配数均为 `54 allocs/op`。这是当前提交的同机趋势样本，不是跨硬件 SLO、发布阈值或独立质量证据。
- 已验证：干净提交 `4bf3fe84bd80023bb5d6e63b1c0e05940bba3015` 的结构化基准（`count=5`、`GOMAXPROCS=1,4`、本地 runner 类别 `local-baseline`）原始输出哈希为 `034c99091449e58de5bf105162885ec7ddc3f99049a2244f2d70c83a007d8b9c`；顺序/并行总体中位数分别为 `7616.5`/`5650.5 ns/op`，均为 `59 allocs/op`，CPU4 并行中位数 `3085.0 ns/op`。相对上一份同设置快照无实质回退；这些是本机趋势证据，不是跨硬件 SLO 或独立质量结论。
- 已验证：提交 `0b3db0e8e343de6268defa3614117dc30e772e5a`（含 SQL 窄门修复）的同设置结构化基准原始输出哈希为 `043c9b6200c72a52a1b12cc8cf2d75adeb578ab242cf6b1cd236eb2d82c4c72c`，报告文件哈希为 `4573997da3e68d759755c5cce3e64e1219353351a7f28e1a5f84849407675914`；顺序/并行总体中位数为 `7650.5`/`5616.5 ns/op`，CPU4 并行中位数 `3056.0 ns/op`，均为 `59 allocs/op`。与历史本机快照处于同一波动范围；仅作为可重复趋势证据，不代表跨硬件 SLO 或持续性能基线。
- 已验证：提交 `7ceedf08243de892db239031befc4209554a5858`（收紧 quoted-AND-SELECT 函数/上下文门禁）的同设置结构化基准原始输出哈希为 `7d8a00cf91b279ce03239b2cfaa430cf29627fdcad00685cd7b95097c877f00e`，报告文件哈希为 `8ea7ba41dcc5a2360c6cb8262442cb2dd399d06d6675c0775287cf9d7f435e2f`；顺序/并行总体中位数为 `9690.5`/`7248.5 ns/op`，CPU4 并行中位数分别为 `8919.0`/`4046.0 ns/op`，均为 `59 allocs/op`。该次运行工作区干净、Go `1.26.6`、Darwin arm64；数字只用于同一 runner 的趋势对比，不作为跨机器回退判定或 SLO。
- 已验证：为排除 runner 波动，同机以 `count=3` 对照提交 `0b3db0e8` 与 `7ceedf08`；当前/基线 CPU1 并行中位数为 `10434`/`10350 ns/op`（约 `+0.8%`），CPU4 并行为 `4069`/`4055 ns/op`（约 `+0.3%`），CPU4 顺序为 `8802`/`8824 ns/op`（约 `-0.2%`）。对照报告哈希分别为 `00b89395780df82d1fb146238b686830ba5bde883d61891df67e2b6e8428256b` 和 `db54402a867a8d3bc73e694803c48700ea5a8b3fb3206af7966d28ce1ffb56f3`；差异处于本机短样本波动范围，不构成跨硬件结论。
- 已验证：本地全量治理（11 个必需来源、3 个 optional 声明）产出 `123051` 条 canonical、`11417` 条重复隔离、`0` 条结构拒收；解析/UTF-8/超长预算均为零，label conflict 与 repair 计数分别为 `3` 和 `127`，formal/quarantine/manifest 对账通过。历史短基准（single-run、固定混合请求；现已由结构化多样本脚本取代）顺序 `169083 ns/op`、并行 `142041 ns/op`，仅作本机历史样本，不作为当前基线、SLO 或质量证据。
- 已验证：检测器 fork/merge 对嵌套 map、slice、array、pointer 和导出 struct 字段做递归快照，保留 fork 内别名并避免兄弟任务共享可变元数据；split 配置和治理 manifest 拒绝符号链接、超大文件、非法 UTF-8、重复 JSON 键和打开期间文件替换。
- 已验证：请求体收集与 100ms 检测 CPU 预算分离；完整读取和解码成功后才原子发布 replay snapshot，失败、过载或取消不会安装前缀或在返回后晚写 Request。未知长度超限由代理明确映射为 413，空 GET/HEAD 保留重试、缓存、压缩和故障转移资格。
- 已验证：请求体读取槽位耗尽属于服务端暂时过载，代理统一返回 503；普通客户端读取/格式错误仍保持原有 400/500 映射，避免把容量问题归因于请求方。
- 已验证：对官方公开回归夹具的临时审计共检查 `154` 行；全量均留在研究隔离区（`formal=0`，重复关系保留），不生成独立 blind 或 FPR/TPR 证据。该审计只用于发现适配/标签问题和定位缺口；其中含有标签不自洽的“良性”负例，不能把任何 opt-in 子集误读为独立良性分母。
- 已验证：对公开良性请求包的 8 个最小压缩片段仅做临时、脱敏、研究性回放；1493 行经治理后只有 796 行进入研究 formal 子集。SQL 低上下文注释/括号指纹门控与通用 `filename` 远程包含窄门控将该子集的观测误报从 `30/796` 降至 `0/796`。该结果没有独立攻击标签，不能替代 blind 或跨站点质量证据，正式分母保持不变；显式 `include`/`require` 入口的无扩展名远程包含覆盖仍由回归测试固定。
- 已验证：2026-09-01 对七个公开研究隔离文件做了一次完整 opt-in 复测；有效请求级分母为 `28947` 条 benign、`15641` 条 attack，观测 `144` 个 FP（`0.49746%`，99% 单侧上界 `0.60335%`）和 `12859` 个命中（`82.2134%`，99% 单侧下界 `81.4910%`）。另有 `12` 条 multipart 输入覆盖不完整、`2` 条构造跳过，均未计入率且使该测试显式失败；报告哈希为 `44a6d63af204d63b71c5579261c65bf5c9436d6d7f57e46f32674570c99dfa8f`。这些数字仅用于隔离区缺陷定位，不是独立 blind、泛化或发布质量证据。
- 已验证：针对上述隔离回放中具备完整请求上下文的 4 条 SQL 漏检（`ai-waf-dataset#875`、`#1688`、`#1703`、`#1707`）做了修复后的定向重放；当前 Analyzer `4/4` 命中 `sqli`，未修改任何正式/训练/盲测分母。该结果仅证明这些已知形态的回归修复，不外推为整体 TPR。
- 已验证：对 13 条带引号拼接、子查询 `WHERE` 数值谓词的隔离 SQL 形态做定向重放，当前 Analyzer `13/13` 命中；同时补入 Oracle 管道等待、Firebird 系统表等窄形态。另一个 `18` 条 `SELECT/FROM` 小子集有 `13` 条命中，剩余 `5` 条均为没有请求注入边界的纯 SQL 词法/批量脚本片段，继续留在隔离区，未为追求命中率放宽通用 SQL 规则或改变任何质量分母。
- 已验证：针对隔离回放中 5 条完整请求上下文的 `%u2216` Unicode 路径分隔符 LFI 漏检，新增仅限 LFI 分析视图的窄折叠（原始 payload 保留），固定回放测试 Analyzer `5/5` 命中，独立 LFI detector 也有代表性覆盖；数学符号、文档说明和非敏感路径负例保持清洁。未修改全局 URL/Unicode decoder，也未改变正式、训练或盲测分母。
- 已验证：隔离回放中的 4 条 SSTI 漏检中，`{{beans.get('runtime').exec('id')}}` 具备明确的模板运行时执行语义；提交 `8c64aff6` 增加独立危险行为窄门，并用局部文档语境抑制教学示例误报。该形态及文档负例回归、竞态测试均通过；`${.now()}`、`${.version}`、`{{config}}` 仍因证据不足留在隔离区，未为追求 TPR 放宽通用占位符规则。
- 已复核：上述隔离失败转储早于最近几轮窄门修复；抽查的 `data:text/html` XSS、`%u2216` Unicode 分隔符 LFI，以及适配器解码后的换行命令链在当前代码均已命中。剩余失败主要属于跨类别标签、无攻击证据或缺少完整请求上下文的记录，没有足够证据再放宽通用规则；不改变任何正式分母。
- 已修复：外部隔离基准在一次运行开始时会先清空 `SEMANTIC_EXTERNAL_BASELINE_FAILS` 指定的失败转储，再由各来源追加当前行；复用同一路径不会混入上次运行的 FP/FN。失败转储路径拒绝符号链接，并由回归测试固定这一行为。
- 已接线：外部隔离基准报告现在附带 `provenance`：运行时间、完整代码修订、工作区 dirty 状态，以及每个输入文件的字节数与 SHA-256。只有输入哈希和 Git 状态齐全且工作区干净时 `provenance_complete=true`；否则报告明确标记为不可复现，不能与当前代码或失败转储直接比较。报告输出拒绝最终组件符号链接并采用临时文件原子替换，避免复用旧链接时改写意外目标或留下半份 JSON。
- 已验证：提交 `ce8269ad5b400bdfe0c66dbadf494c0bb023f4a1` 快照点的结构化语义基准（`count=3`、`GOMAXPROCS=1,4`、Go `1.26.6`、Darwin arm64）报告文件哈希为 `0b30b2a54fac15390bd1ede238b6bd3558ca2919d25ebd26e189197e7f3979d9`，原始输出哈希为 `dccb6ea3af99adc231d99518b4d06219b0d7e08dc0c274d45093b33fd4939497`；顺序/并行总体中位数分别为 `8579.5`/`6396.0 ns/op`，CPU4 顺序/并行中位数分别为 `7763.0`/`3470.0 ns/op`，均为 `59 allocs/op`。该结果仅作同一 runner 的可重复趋势证据，不是跨硬件 SLO 或独立质量结论。
- 已验证：提交 `f6956ced` 的无分配热路径优化后，结构化语义基准（同一 `count=3`、`GOMAXPROCS=1,4` 设置）报告文件哈希为 `63c704c61060bd9f4ccf1e5401bd1995edcbb56e741362c0e184cae92fe50453`，原始输出哈希为 `95ff19752a0ac2d9833a4402d3dc1b9eb8eac0af8848d0909e0c87066a496431`；顺序/并行总体中位数为 `8174.0`/`6229.5 ns/op`，CPU4 顺序/并行中位数为 `7459.0`/`3425.0 ns/op`，均为 `54 allocs/op`。相对前一快照，混合请求路径的分配数下降 5 次/请求；该结果仍仅作同一 runner 的趋势证据，不是跨硬件 SLO 或独立质量结论。
- 已验证：提交 `a39b9cde59b572b91457764e985cf5e24795a3e1` 的干净工作区结构化基准在同一 runner、`benchtime=1s`、`count=3`、`GOMAXPROCS=1,4` 下完成；CPU1 顺序/并行中位数为 `9831/9979 ns/op`，CPU4 顺序/并行为 `8717/4168 ns/op`，均为 `54 allocs/op`，未出现分配回退。报告文件 SHA-256 为 `fb8db8ddf6925d8929104f82bc75e0fb9bc9ca68a4783160d9daaa05adfb9ef7`；该样本仅用于同机趋势对比，不是跨硬件 SLO 或发布阈值。
- 已验证：代码快照提交 `e1549399f6f3e87f3fdfdf8bffa5e36ba5dfdab3`（本条文档证据随后单独提交）在同一 runner、`benchtime=1s`、`count=3`、`GOMAXPROCS=1,4` 下完成结构化基准；报告文件 SHA-256 为 `fbd8f5b386d8c1d1578dd6198f7b53805c6279e2dc1694bf5823914ebd14e3c0`，原始输出 SHA-256 为 `7f22df7ab45afc17673f410e6e82a7c298d54da4863719028d686a430dc8b056`；CPU1 顺序/并行中位数为 `9198/9165 ns/op`，CPU4 顺序/并行为 `7588/3462 ns/op`，分配数均为 `54 allocs/op`，工作区 `dirty=false`。该样本只用于同一 runner 的趋势核对，不是跨硬件 SLO、发布阈值或独立质量证据。
- 已验证：针对 36 条带 URL sink 字段的合法 `data:text/html;base64` XSS 隔离形态及 1 条 data-URI 路径形态，固定回放测试 Analyzer `36/36` 命中，独立 XSS detector 有代表性覆盖；新增字段名、媒体类型、base64 可打印性和解码后可执行 HTML 的联合门控，安全 HTML、`text/plain`、非 URL 字段和文档负例保持清洁。其余因语料转小写而失去合法 base64 字节语义的隔离样本继续保留，不为追求命中率放宽解码规则。
- 已验证：提交 `492223b1` 后在干净工作树执行结构化语义基准（`go1.26.6`、darwin/arm64、`benchtime=1s`、`count=3`、CPU `1,4`）；顺序中位数 `9870.5 ns/op`，并行中位数 `7330.5 ns/op`，CPU4 顺序/并行分别为 `9181/4303 ns/op`，均为本机可重复性样本而非跨机器 SLO。报告 SHA-256：`429645bffa1d632eed7c8829de4d1a34c5da0c186b25858e0a52e0fa7328e79b`。
- 已验证：提交 `c6ab88d7`（Unicode LFI 与 data-URI XSS 窄门）后的干净结构化基准使用同一设置；顺序/并行中位数分别为 `9751.0`/`7370.0 ns/op`，CPU4 顺序/并行分别为 `9097/4337 ns/op`，均为 `59 allocs/op`，报告 SHA-256 为 `d67cfd989baad16e9532dd0a43016426ca659eead487790b15001adaa722c806`。与前一份本机快照处于同一波动范围，不构成跨硬件 SLO 或独立质量结论。
- 已验证：在提交 `d6e5c65a` 快照点（此前已接入 SSI/LFI 窄门与治理配置严格加载）按同一设置采样 `count=3`、`GOMAXPROCS=1,4`；顺序/并行总体中位数分别为 `8537.0`/`6427.0 ns/op`，CPU1 顺序/并行为 `9328/9354 ns/op`，CPU4 顺序/并行为 `7783/3531 ns/op`，均为 `59 allocs/op`。报告 SHA-256 为 `4b5e0f6bee0b1298b1f72f3d05011dcb3c5331c80dce07be1ed0dcc7eabf74cd`，原始输出 SHA-256 为 `146ccdfa752e1e2fd8ec01e7c8b734fb737aa54c977da08f16ca6888cb440eca`；仅作为同一 runner 的趋势样本，不宣称跨硬件 SLO 或独立质量改善。
- 已验证：代码提交 `ada2b5f25869c5cfbb90d33f5f9287c4350f19db` 的干净工作树结构化语义基准在 `benchtime=1s`、`count=3`、`GOMAXPROCS=1,4`、Go `1.26.6`、Darwin arm64 下完成；报告 SHA-256 为 `b8f55e44a5a94e598d84ef2171ee1fb8358d19f8222e451480c64629651d5c41`，原始输出 SHA-256 为 `cd4a99d0d51b3441c866d175ad5fa4892be79a323c5f15d5a26c7e4d9b708180`。顺序中位数 CPU1/CPU4 为 `9166/7587 ns/op`，并行中位数 CPU1/CPU4 为 `9204/3463 ns/op`；所有样本均为 `54 allocs/op`，bytes/op CPU1/CPU4 为 `11286/11288`。该样本仅用于同一 runner 趋势，不能作为发布 SLO、质量门禁、独立 blind 或泛化证据。
- 已接线：截断、畸形或超限 multipart 会产生可审计的 input-incomplete 信号并应用 open/observe/closed fail-mode，不再作为 clean pass；已经确认的 block/challenge 仍优先。语义候选公平采样和有界并发的定向竞态/资源测试均已通过。
- 已验证：2026-09-01 在允许回环监听的受控环境执行 `go test ./... -count=1 -timeout=300s`，全仓所有 Go 包通过；其中 `cmd/cheesewaf-corpus`、`internal/engine`、`internal/security`、`internal/proxy` 的完整 CLI/代理回归均通过。此前受限沙箱中的 `[::1]:0` 绑定失败仅是环境限制，不是测试或实现失败。
- 已验证：2026-09-02 对 `cmd/cheesewaf-corpus`、`internal/engine`、`internal/security`、`internal/proxy` 执行完整 `go test -race` 均通过；语义包另对高并发管线、并行候选、缓存、预算公平性、取消传播和 SQL 候选去重回归执行定向 `go test -race` 并通过。该证据覆盖竞态安全，不替代独立 blind 质量评估。
- 已验证：2026-09-02 在受控回环环境对当前提交执行 `GOCACHE=/private/tmp/cheesewaf-gocache go test ./... -count=1 -timeout=300s`；全仓所有 Go 包通过，语义包完整评估耗时约 `292.5s`，未触发超时。
- 已验证：2026-09-02 重新执行 `make security-corpus`；哈希绑定的正式快照为 `14,333` 行（benign `293`、attack `14,040`），治理回放、类别门禁和评估均通过。该快照仍是仓库内受治理回归，不替代独立 blind 泛化证据。
- 已验证：2026-09-02 对同一公开研究隔离快照在干净提交 `a39b9cde59b572b91457764e985cf5e24795a3e1` 上重复回放；明确剔除并使测试失败的 `14` 条 coverage-incomplete 记录及 `2` 条不可构造记录不计入率。有效分母为 benign `28,945`、attack `15,641`；FP `97`（`0.335%`，99% 单侧上界 `0.424%`），其中无攻击特征的干净负例 FP `1/28,945`（约 `0.004%`）；命中 `13,000/15,641`（`83.11%`，99% 单侧下界 `82.41%`），标签可信攻击行命中率 `96.91%`。MIME wildcard SQL 指纹门控、相对 XPath、原始 HTTP SSI、multipart/PDF 与 JSON 尾随注释、HTML entity/Cookie 传输结构、遥测 referrer/SVG namespace 和短句式 LFI 误报门控均有定向回归；临时报告 SHA-256 为 `93448f53221d964985f800970e8405ecd31b3b64d03881067243adffbdb2f9f9`。该结果仍属于公开研究隔离集，不是独立 blind、泛化或发布质量证据，不能替代授权环境中的持续验证。
- 已验证：本次无分配热路径改动的相关定向竞态回归通过；本机完整 `go test -race ./internal/engine/semantic -short` 在大型 `TestEvaluationPlatform` 达到 120 秒测试超时，未产生 race 报告。该限制属于评估规模/本地超时环境，完整包应在 CI 或更长超时下执行，不能把超时误读为并发泄漏或检测失败。
- 已验证：2026-09-01 对公开来源做了只读准入审计；[SR-BH 2020](open-corpus-catalog.md) 具备公开版本和 CC0 记录但仍有单一 WordPress 环境、WAF 派生标签及 PII/Cookie/Token 清洗风险；[ModSec-WP](open-corpus-catalog.md) 的官方 API 现已确认 `access_right=open`、CC BY 4.0 和文件校验值，但它仍是单一测试床，存在近重复、WAF 派生标签和请求字段清洗/标签独立性风险；[openappsec 良性包](open-corpus-catalog.md) 没有独立攻击标签；Biblio-US17 需按资源页申请且仅公开 URI 粒度，已明确排除；一个公开页面标注 CC BY 4.0 的 SQLi 候选因文件/字段/哈希证据不足仍留在隔离区。以上来源均未进入 formal/blind、未改变任何质量分母；H23Q/AWID、第三方合并仓库和需要申请/机构认证的来源已明确排除。ModSec-WP 的受控副本只允许在隔离目录做请求字段转换和全局治理审计，规则/响应/标签字段不得进入 analyzer。
- 已验证：2026-09-02 对 ModSec-WP v2 受控副本完成一次全局治理审计；官方文件 SHA-256 为 `f959c79e185502b03206f6fdeb29306a65571394c2f009dda503d43ba306d16d`。跨现有语料与该副本共 `243351` 行全部留在 `research-quarantine`（`formal=0`），其中重复隔离 `101826` 行；ModSec-WP 去重后候选为 `18418` 条（attack `17295`、benign `1123`），候选清洗排除 `237` 行，可信标签子集为 `11884` 条。当前 analyzer 隔离回放报告（输入 SHA-256 `d625117c47ed4c07a3e4e98d85f0230d1a6791d9b68615d24f75708f5fd3dcaf`，报告 SHA-256 `86fd22a673acf0cc43d81bf23248f45e9e8e6a8ef1731fbcb43e40c24a28721e`）命中 attack `14263/17295`（`82.4689%`），benign FP `15/1123`（`1.3357%`）。15 条 FP 全部是 `normal` 标签但请求本身含明确 `/etc/passwd`、`/etc/group` LFI 或 `cmd=` 命令执行载荷：`normal#10015`、`normal#10026`、`normal#9472`、`normal#9475`、`normal#9489`、`normal#9494`、`normal#9507`、`normal#9520`、`normal#9526`、`normal#9534`、`normal#9558`、`normal#9579`、`normal#9589`、`normal#9603`、`normal#9618`。它们按标签冲突留在隔离区，不能通过 detector 抑制来伪造低 FPR。排除这 15 条冲突后的 clean-negative 观测为 `0/1108`，仅用于说明标签噪声，不是独立泛化或发布门禁；该来源不进入 formal/blind，也不改变任何质量分母。
- 已登记：只读核验了 [REDI Web logs de DVWA（V1）](open-corpus-catalog.md) 的公开记录；官方元数据给出 CC BY 4.0、`access.log`/`error.log` 与 `sqlmap.zip` 的文件级大小/MD5，并描述正常访问与 B/E/U/T/Q SQLi 日志。数据集列表标为 Public，但单个文件页出现“确认/补充信息后申请访问”的条件提示，故无需门槛尚未确认；该来源还是单一 DVWA 生成环境，仍需确认完整请求上下文、逐行标签对应、PII/Cookie/Token 清洗和跨组独立性。本轮不确认、不申请、不下载、不进入 train/formal/blind，后续副本必须先与现有语料全局去重、初筛、语义挑选、清洗和二次复核。
- 已修复并复核：提交 `0d66ad5c`/`3b317c9a` 将 legacy analyzer/http/stream/gate 语料回放中无法构造或解析请求的 `warning` 改为 fail-closed；warning 保留诊断，同时保留对应 benign/attack 分母、计入失败（attack 计为 missed），不再以静默跳过缩小指标。新增流式 NDJSON 回归覆盖 warning 结果、失败返回和分母守恒；`go test ./cmd/cheesewaf-corpus` 及独立复审通过。
- 已验证：代码提交 `3b317c9a` 上通过 `go test ./... -count=1 -timeout=420s`、受影响包的 `go test -race`、`go vet ./...`、`git diff --check` 与 CI 静态回归；语义评估包完整测试耗时约 `292.4s`，未触发超时，随后仅追加审计文档，工作区保持干净。
- 已留档（scope 分离前的旧 schema 诊断）：2026-09-02 在代码提交 `3b317c9a556e801a1689e9f59a55e0b335da4e21` 上执行 `SEMANTIC_EVAL_SHARDS=8` 的确定性分片回放并合并；报告 SHA-256 为 `f6cf4ac3e3662f7d5436880d60b7b71909c5e9a58dc2e620d4d7ed5d6aa74e5c`。该报告将来源混合为单一汇总：`66577` 条 benign、`23176` 条 attack，FP `26`（`0.039053%`，99% 单侧上界 `0.061383%`），命中 `21621/23176`（`93.337936%`，99% 单侧下界 `92.946672%`）。其中 `external_dataset` 是 payload-only 记录包装成固定请求的诊断集，不具备独立完整请求上下文；该旧汇总不能当作当前 request-level blind 或泛化证据。失败样本与来源/类别摘要保留在临时报告目录，未写入仓库。
- 已验证：2026-09-02 在代码快照 `cdad90c7306ed32bbe228f57844d4c5fba6e7bc6` 上按显式 `scope` 完成 8 分片回放；随后以提交 `39c7ca71`（基于 `68b971e0`）的合并脚本修正来源级 F1 单位、零命中边界和未舍入计算并重算，合并报告 SHA-256 为 `ee40cd6028612ca97aa6d02980ab21970f386788735fe7cafe7ab2b4be3fee54`。request-only 主视图（`curated_corpus` + `mined_probe`）为 benign `11594`、FP `0`（FPR `0%`，99% 单侧上界 `0.046657%`），attack `17034/17034`（TPR `100%`，99% 单侧下界 `99.968239%`）；该视图才用于质量门禁。`all_sources` 仅作混合诊断：benign `66577`、FP `26`（FPR `0.039053%`，上界 `0.061383%`），attack `23176`、命中 `21632`（TPR `93.337936%`，下界 `92.946672%`）。其中 `external_dataset` 明确为 payload-only（benign `54983`/FP `26`、attack `6142`/命中 `4598`），不能充当独立 request-level 或 blind 证据；本次没有改动正式/训练/盲测分母，报告与失败样本均保留在临时目录。
- 已修复：提交 `017ee56d` 为混合文件的 paranoia sweep 增加 scope 隔离回归；`payload-only` 的 benign/attack 只进入 all-sources 诊断，request-only 主视图不再被未来的混合载荷文件污染。每条样本仍只执行一次检测并复用命中结果进行 0-5 级离线分级。
- 已登记：2026-09-02 对 [Superviz25-SQL](open-corpus-catalog.md)、[PMT MLSec 的 CSIC 2010 页面](open-corpus-catalog.md) 和 [LSPR25（Zenodo）](open-corpus-catalog.md) 做了只读 blind 候选复核。前者虽有公开版本、文件哈希和 MIT 说明，但实例是单一部署的合成 SQL 查询而非完整 HTTP 事务，标签由生成器/`sqlmap` 产生；CSIC 页面虽声明 raw HTTP 和 SHA-256，但为 research-use、原始入口需 request form，且缺少去敏与跨组独立证据；LSPR25 为受限登录流级数据，不是完整 HTTP 请求，也缺少文件级许可/哈希和去敏证据。三者均留在隔离区或明确排除，未下载、未申请、未进入任何正式分母。
- 可选后续（不阻塞当前工程目标）：用独立且已锁定的开放来源生成正式 blind 快照。当前仍没有同时满足文件级许可证、精确版本、完整请求上下文、独立标签、去敏和跨组独立性的开放原始请求；现有 payload-only、批量派生和本地合成文件不能充当独立 blind。若未来取得合法来源或在授权靶场生成流量，仍须走同一套全局去重、初筛、语义挑选、脱敏、分组切分和首次锁定流程；在此之前不生成虚假的独立泛化指标。当前工程闭环由 `scripts/ci/run-authorized-blind-lab_test.sh` 覆盖，它只验证本地治理/切分/回放/锁定接线，不冒充外部质量证据。性能基准脚本和本机趋势采样已接线，后续只需在 CI/授权环境持续积累样本，不把单机短样本当作发布 SLO。
