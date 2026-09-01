# 开放语料与日志目录

本目录记录可作为 CheeseWAF 语义检测研究候选的开放来源，以及它们能支持的
数据粒度。目录只做来源登记和准入约束，不执行下载、不保存外部原始数据，
也不把「公开可访问」等同于「允许再分发或商用」。在进入任何训练、调参或
评估流程前，仍必须完成 [语料治理流程](semantic-corpus-governance.md)。

目录中的链接仅用于人工核验来源和许可证；本阶段不自动抓取、不申请账号，
也不会因某个来源数量较大而改变正式评估分母。

## 准入原则

所有来源（包括仓库已有语料和新生成的本地样本）必须与现有数据一起执行：

1. 全局精确去重和规范化指纹去重；
2. 结构初筛（编码、长度、请求形状、标签和可适配性）；
3. 语义挑选（类别证据、业务上下文、协议粒度和标签保真度）；
4. PII、凭据、Cookie、Token 和其他密钥清洗；
5. 逐文件许可证、署名、商用和再分发核验；
6. 隔离区二次复核、按 source/site/session 分组切分，再决定是否进入 formal。

缺少任一证据时，记录仍可用于研究隔离或本地生成，但不得进入正式训练集、
正式回归快照或独立盲集。原始载荷和日志不写入报告；审计文件使用哈希、伪名
和行号标识。

## 候选目录

下表是来源类别和用途登记，不代表本仓库已经接入或认可其中的全部文件。使用
前应锁定精确提交、文件路径、下载日期（如适用）和文件级许可证证据。

| 来源 / 入口 | 粒度与标签 | 访问门槛 | 初始用途 | 准入状态 |
| --- | --- | --- | --- | --- |
| [openappsec WAF Comparison Project](https://github.com/openappsec/waf-comparison-project) Legitimate Requests Dataset | 约 1,040,242 条真实浏览操作产生的完整良性 HTTP 请求，按站点/业务类别分组 | 公开直链；无需账号或申请 | 独立 benign 候选、路径/参数/Header 分布和长尾白流量 | `research-quarantine`；须先做全局去重、PII/第三方内容清洗、文件级许可复核和分组切分 |
| [SR-BH 2020 multi-label dataset](https://dataverse.harvard.edu/dataset.xhtml?persistentId=doi:10.7910/DVN/OGOIXX) | 约 907,814 条带时间、目标、Header/Cookie、请求体和响应字段的 WordPress HTTP 请求；normal/attack 与 13 类 CAPEC 标签 | Harvard Dataverse 公开记录；无需申请，但原始日志仍含 PII/凭据样式风险 | 跨来源 benign/attack 候选、时间切片和长尾请求 | `research-quarantine`；需锁定文件版本/哈希、完成去敏与独立标签复核后再评估 |
| [REDI Web logs de DVWA（V1）](https://doi.org/10.60895/redata/G4HCSX) | 公开记录包含 `access.log`/`error.log` 以及 `sqlmap.zip`；描述为 DVWA 正常访问与 SQLi（B/E/U/T/Q）攻击日志，文件级大小与 MD5 可查 | 数据集列表标为 Public、CC BY 4.0 且公开 API 地址可见；但单文件页出现“确认/补充信息后申请访问”提示，是否真正无门槛尚未确认 | 独立 SQLi/良性候选、日志适配和时间/会话分组研究 | `research-quarantine`；在访问条件明确前不下载、不申请；单一 DVWA 生成环境且攻击由 sqlmap 产生，须先确认压缩包是否保留完整请求上下文、校验哈希、去敏、全局去重和标签复核，不能直接作 blind |
| [ModSec-WP / WordPress Web Attack Audit Log Dataset](https://zenodo.org/records/21872151) | v2 约 108,883 条完整 HTTP 事务，`combined_final_dataset_augmented.xlsx`（约 27.8 MB，MD5 `6d02547829e0b460ef6473d5603a84db`），含请求/响应、Header、Body 和 `sqli`/`xss`/`fileinclusion-ldf`/`rce`/`bruteforce`/`normal` 六类标签；单一 WordPress 测试床 | Zenodo 记录标为 Open、无需申请；但本项目尚未确认文件级许可证/权利证据 | WordPress 业务形态和攻击邻居参考 | `research-quarantine`；标签由场景关联、规则匹配和专家复核混合产生，且页面提示有大量近重复请求，不能直接作为独立 blind |
| [Thirty-Day OWASP ModSecurity production blocked requests](https://zenodo.org/records/17178461) | 约 30 天生产 Web 服务器被 OWASP CRS 拦截的匿名恶意 HTTP 请求，`owasp.zip` 约 29.5 MB，MD5 `95b7a8237abc163d8ca31e49f7318efd`；仅攻击侧、非 benign/attack 配对集 | Zenodo 记录标为 Open、无需申请；当前记录的 Rights/License 字段未提供可核验文件级许可 | 攻击请求形状、CRS 规则覆盖和 hard-positive 参考；不能支撑 FPR 或完整 blind | `research-quarantine`；先确认文件级许可证、请求字段/时间与会话边界、去敏和标签来源，再与现有语料全局去重、初筛、语义挑选、清洗和二次复核；不下载、不进入 formal/blind |
| [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset) 回归测试夹具 | HTTP 请求形状、规则期望结果、攻击类别线索 | 公开仓库；具体测试文件仍需逐文件核验 | 攻击邻居、协议差分、规则回归 | 候选；仅在 Apache-2.0 及文件级证据确认后进入治理 |
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) 本地应用 | 通过本地靶场生成的请求/响应；标签由已知路由和动作产生 | 公开仓库；数据由本地生成，不搬运生产日志 | 生成良性业务流量和可重复攻击重放 | 候选生成器；生成物单独去重、脱敏和复核 |
| [OWASP WebGoat](https://github.com/WebGoat/WebGoat) 本地应用 | 教学场景的请求/响应和步骤标签 | 公开仓库；仅使用本地靶场 | 生成跨协议和上下文样本 | 候选生成器；GPL 条款和生成物许可需记录 |
| [Zeek](https://github.com/zeek/zeek) 仓库中的示例日志 | 连接、HTTP、DNS 等结构化日志，通常没有攻击金标准 | 公开仓库；示例文件需逐文件核验 | 日志 schema、正常流量形状、压力回放 | 参考/候选；不能直接当 HTTP 攻击标签 |
| [Suricata](https://github.com/OISF/suricata) 测试夹具 | 规则告警、PCAP 或协议样本 | 公开仓库；代码与测试数据许可可能不同 | 规则联动和协议压力 | 研究隔离；逐文件许可证与再分发证据齐全后再评审 |
| [OpenTelemetry Demo](https://github.com/open-telemetry/opentelemetry-demo) 生成日志 | 合成服务日志、追踪和指标，无真实用户身份 | 公开仓库；合成数据 | 可观测性字段、并发和资源压力 | 参考/候选；不替代请求级攻击金标准 |
| 本地合成 HTTP 流量（固定路由、参数和响应） | 完整请求级 benign/attack 对，标签由生成脚本确定 | 无外部访问门槛 | 补齐站点、会话、时间切片和硬负例 | 首选；脚本版本、种子和输出哈希必须入 manifest |

### 训练集参考来源的条目级准入结论

本轮只核验来源说明、粒度和许可证声明，不下载原始数据。以下来源即使公开，
也必须先与现有语料做全局去重、初筛、语义挑选和清洗；在请求上下文、许可证
或标签证据不足时，只能留在研究隔离区：

| 来源 | 核验结论 | 允许用途 |
| --- | --- | --- |
| [HttpParamsDataset](https://github.com/Morzeux/HttpParamsDataset) | 仓库声明 MIT，但记录是可嵌入 HTTP 参数的孤立值，且由多个工具/来源混合生成；不是完整请求 | 训练阶段的参数形状与 hard-negative 参考；不得直接计入请求级 FPR/TPR 或 blind |
| [CSIC 2010 HTTP Dataset 镜像](https://github.com/sunbeamdotpt/csic-dataset) | 具有完整 raw HTTP 和 normal/anomalous 划分，但镜像明确说明数据文件没有 stated license，仓库 Apache-2.0 不覆盖数据文件 | 在取得原始权利人/文件级许可证证据前不得接入；不下载、不进入 formal/blind |
| [Superviz26-SQL](https://zenodo.org/records/19627322) | 数据表明为 MIT，但内容是合成 SQL 语句而非 HTTP 请求；其生成器还提示攻击样本未逐条验证 | 仅可在本地受控靶场包装成请求后作 SQL 语法邻居；先治理，不能直接作请求级 blind |
| [WEB-IDS23](https://github.com/sys-uos/web-ids23) | 公开 DOI 的 Zeek/FlowMeter 流级 CSV，含 HTTP/S 类别标签，但不是原始 HTTP 请求 | 仅作流量类别和压力参考；不得直接送入语义请求检测器 |
| [Normal & Malicious SQLi](https://data.mendeley.com/datasets/sx84kj3xfz/1) | 官方页面称超过 64,000 条 benign/SQLi web-request 记录，版本 1，CC BY 4.0；页面未公开字段字典、文件哈希或标签生成细节 | `research-quarantine` 候选；不申请账号、不下载前先确认匿名可取、完整请求字段、文件级哈希、去敏和标签独立性；不得直接进入 formal/blind |

### 训练参考来源的补充审计（2026-09-01）

本次只核对官方记录、版本、粒度和许可说明，没有下载完整外部数据，也没有改变
任何 `formal`、`train` 或 `blind` 分母：

- [SR-BH 2020 官方记录](https://portalcientifico.uah.es/documentos/668fc479b9e7c03b01bde810?lang=es)
  标注版本 1.2、CC0 1.0、12 天的 2020 年 7 月采集窗口和 907,814 条请求。它的
  请求上下文比 payload-only 集完整，但采集自单一 WordPress 暴露环境，标签经过
  ModSecurity 检测结果的人工/半自动修订，且字段包含 IP、Cookie、Token 样式值和
  第三方内容风险。即使公开可取，也必须先保存精确文件哈希和许可证据、全局去重、
  初筛、语义挑选、PII/凭据清洗、按 site/session/day 分组，并由独立复核确认标签；
  在此之前只留在 `research-quarantine`。
- [ModSec-WP v2](https://zenodo.org/records/21872151) 页面列出 108,883 条事务、
  `combined_final_dataset_augmented.xlsx`（约 27.8 MB，MD5
  `6d02547829e0b460ef6473d5603a84db`）和六类标签。记录说明数据来自单一 WordPress
  测试床的 detection-only WAF，标签结合时间/执行关联、规则匹配和专家复核，且自动化
  工具会产生大量近重复请求。当前仍没有可供本项目确认的文件级许可证证据，因此只
  能帮助定位 WordPress 形态缺口，不能作为独立攻击标签或 blind 分母；取得受控副本
  后仍须走同一套全局去重、初筛、语义挑选、清洗、分组和二次复核。
- [openappsec Legitimate Requests Dataset](https://github.com/openappsec/waf-comparison-project)
  目前只能作为 benign-only 候选。它没有独立攻击标签，不能单独支撑 TPR；完整压缩包
  较大且真实站点内容可能包含第三方数据，所以仍不自动下载或接入。
- [Biblio-US17 官方资源页](https://dtstc.ugr.es/neus-cslab/recursos/ds-biblio/)
  明确说明数据在仓储中“under request”，并且公开描述的记录粒度只有方法、URI、协议、
  响应码/大小等字段；即使页面称其为公开数据，也不满足当前“无需申请且带完整请求上下文”
  的准入条件。因此不申请、不下载、不放入候选分母；若未来取得合法副本，也必须先完成
  文件级许可证核验、全局去重、初筛、语义挑选、脱敏和独立标签复核。
- [Normal & Malicious SQLi 的 Mendeley Data 页面](https://data.mendeley.com/datasets/sx84kj3xfz/1)
  显示版本 1、CC BY 4.0 和超过 64,000 条 web-request 记录，但当前页面没有文件名、字段
  字典、精确哈希或匿名下载验证。本轮只登记为 `research-quarantine` 候选，不登录、不申请、
  不下载；只有在这些证据齐全后，才可将副本送入统一去重、初筛、语义挑选、清洗和分组流程。
- [REDI Web logs de DVWA（V1）](https://doi.org/10.60895/redata/G4HCSX)
  的官方记录给出 CC BY 4.0、`access.log`/`error.log` 与 `sqlmap.zip` 的文件级
  大小/MD5，以及正常访问和 B/E/U/T/Q SQLi 日志说明；数据集列表和 API 地址显示为
  Public，但单个文件页同时出现“确认/补充信息后申请访问”的条件提示，所以“无需门槛”
  尚未完成核验。它是单一 DVWA 环境生成的受控流量，攻击侧由 sqlmap 产生；因此只能
  作为独立来源候选，不能把“公开”或“有标签”当成真实站点泛化证据。本轮不确认、不
  申请、不下载原始包；后续只有在访问条件明确且确实无需申请后，才可取得受控副本，
  确认压缩包是否含完整方法/目标/Header/Body、上下文与标签能否逐行对应，再与现有语料
  做全局去重、结构初筛、语义挑选、PII/Cookie/Token 清洗、文件哈希锁定、按 site/session/
  时间分组和独立二次复核。在这些步骤完成前，行只留在 `research-quarantine`，不进入
  train、formal 或 blind 分母。
- [Thirty-Day OWASP ModSecurity production blocked requests](https://zenodo.org/records/17178461)
  的官方记录标为 Open，并给出 `owasp.zip`（约 29.5 MB，MD5
  `95b7a8237abc163d8ca31e49f7318efd`）及匿名化、生产环境拦截恶意请求的说明；它是
  attack-only，不能单独提供 benign 分母或独立 FPR。当前 Zenodo 页面没有可核验的
  文件级 Rights/License 文本，因此不把文章或平台默认条款当作数据授权。本轮只登记
  元数据，不下载；后续若访问条件和许可明确，副本仍须先与现有语料全局去重、初筛、
  语义挑选、PII/Cookie/Token 清洗、按时间/会话分组并二次复核，再决定是否作为攻击侧
  研究输入。

这次审计没有发现同时满足“文件级许可可复核、精确版本可锁定、完整请求上下文、
独立标签、跨站点/时间分组和去敏”全部条件的现成开放 blind 文件。后续若取得合法
副本，必须先与仓库现有语料做全局去重、初筛、语义挑选和清洗，再决定是否晋级；不
为了满足样本量而绕过申请、注册、API key、NDA 或授权确认。

上述结论与本目录的准入原则一致：训练参考不等于可发布语料，任何后续副本都要
保存精确版本、文件哈希、许可证证据、清洗记录和分组切分结果。

「候选」只表示可以开始治理，不表示可以直接送入 detector。对于攻击样本，
必须保留完整请求上下文；payload-only、规则文本或文章正文需要在隔离靶场
中重放并记录方法、目标、Header/Cookie/Body、响应和生成器版本，才能转为请求
级样本。

### 公开良性包的首次核验记录

2026-09-01 对上述 WAF Comparison Project 良性直链做了只读 HTTP 元数据核验：
`https://downloads.openappsec.io/waf-comparison-project/legitimate.zip` 返回
`application/zip`、`Content-Length=1,203,983,791`（约 1.20 GB）、
`Last-Modified=2024-12-01T10:07:47Z`、对象版本
`tGpuOS7cmUgoyfNC87zvekuaNdOxL5YV` 和 ETag
`7f7b53e6e8d780e4d390c8070bffce88-71`。官方仓库说明该
良性集与工具采用 Apache-2.0，但数据来自真实网站浏览操作，仍可能包含第三方
URL、内容片段或个人数据；因此本记录只证明来源可复现和无需申请，不证明可直接
商用、再分发或已完成脱敏。本阶段仅允许对已知条目的有限 Range 片段做结构核验，
不下载完整压缩包、不写入仓库、不改变 formal/blind 分母。只有取得受控副本后，才可
在临时目录按 sidecar 记录精确对象版本/哈希，完成全局去重、初筛、语义挑选、
PII/第三方内容清洗、许可证复核和 source/site/session 分组；任何不满足条件的行继续
留在 `research-quarantine`。

### 公开良性包的条目级结构核验

在不下载完整压缩包的前提下，2026-09-01 通过 ZIP 中心目录和单条 HTTP Range
片段核验了 `Legitimate/browsing_2024_bigcommerce_hl.json`：该条目解压后为
37 条 JSON 记录、约 75 KiB，字段形状为 `method`、`url`、`headers` 和 `data`，
可以还原完整的请求方法、目标、Header 和请求体。样本中出现真实站点 Host、浏览器
标识、Cookie/CSRF 类字段以及前端遥测请求；遥测载荷含 Sentry DSN 和会话标识。
这些字段足以证明该来源不是无上下文的 payload-only 集，但也证明真实第三方内容、
凭据样式和个人/会话标识不能仅靠公开链接自动获得准入。当前只保留结构审计证据，
不保存原始值、不改变 formal/blind 分母；后续受控副本仍须先走全局去重、清洗和二次
复核。治理器已对窄格式 Sentry DSN 执行 `secret_detected` 硬隔离并脱敏，其他
Cookie、CSRF 和会话字段仍需逐来源审查。

同日对 8 个最小条目的脱敏临时样本做了一次研究性回放（1493 行先经治理，796 行
进入仅供研究的 formal 子集）。SQL 低上下文注释/括号指纹门控，以及对通用
`filename` 字段的远程包含窄门控，将该子集的良性误报从此前观测的 `30/796`
降至 `0/796`；`include`、`require` 等显式包含入口仍保留无扩展名 URL 覆盖。
该数字只用于发现误报簇和验证回归，样本经过来源筛选、脱敏且没有攻击标签，不能
充当独立 blind、独立泛化或发布质量证据，也不改变正式评估分母。

## 仅研究隔离或明确排除

以下来源不作为本阶段正式数据入口：

| 来源类别 | 原因 | 处理方式 |
| --- | --- | --- |
| HTTP Archive、Common Crawl 等大规模公开抓取 | 访问虽公开，但条款、第三方内容、PII 和再分发边界需逐文件确认；粒度也不是攻击金标准 | 只做 schema/良性形状研究，保留隔离，不改变正式分母 |
| CAIDA、MAWI、其他网络测量 PCAP/流量 trace | 常见注册、使用协议或申请条件，且含高风险原始网络信息 | 不申请、不下载；如已有合法副本，仅做隔离压力分析 |
| [H23Q/AWID](https://icsdweb.aegean.gr/awid/download) 及需机构邮箱/理由审批的下载入口 | 需要 basic authentication、机构邮箱和 justification；且主要是 802.11 PCAP/CSV，不是完整 HTTP 请求 | 明确排除，不申请、不下载 |
| 第三方合并/转换的 ECML/CSIC 数据仓库 | 仓库许可证不覆盖原始数据，部分样本伪造 Header/Cookie，来源/时间/文件权利不可审计 | 仅作参考，不能进入 formal/blind |
| DataCon 或需要申请、注册、API key、NDA、授权确认的数据 | 不符合本项目当前无门槛接入约束 | 明确排除，不进入候选池 |
| Kaggle、私有网盘、登录后才能取得的镜像 | 账号、条款或版本不可审计，许可证可能只覆盖网页而非数据文件 | 不接入；寻找具有文件级许可证的原始来源 |
| 公共 Git 仓库中没有数据许可证的 JSONL、PCAP、蜜罐日志 | 代码仓库的总 LICENSE 不能自动授权第三方数据；隐私和再分发未知 | `research-quarantine`，等待文件级证据和人工复核 |
| URL-only、payload-only、规则/文章正文 | 缺少 HTTP 上下文，直接计入 TPR 会扭曲分母 | 仅作特征参考；须在本地靶场重放后再治理 |

任何来源一旦出现链接失效、许可证变更、PII 泄漏、标签冲突或无法复现的变换，
立即降级为 `research-quarantine`。不为了满足样本比例而绕过申请、许可或隐私
审查。

## Sidecar 登记格式

每个文件（包括本地生成物）旁边保存一份不含原始敏感值的登记记录。最小字段：

```json
{
  "name": "source-name",
  "source_url": "https://example.invalid/source",
  "version": "commit-or-release",
  "retrieved_at": "2026-08-31T00:00:00Z",
  "file_sha256": "sha256:...",
  "license_evidence": "path-or-quoted-file-hash",
  "commercial_use": "review-required",
  "redistribution": "review-required",
  "access": "public-direct|local-generated|research-quarantine",
  "granularity": "http-request|log|pcap|payload",
  "label_provenance": "generator-or-review-record",
  "pii_scan": "pass|fail|review",
  "transforms": ["dedupe", "triage", "sanitize"],
  "allow_formal": false,
  "reviewer": "security-review",
  "next_review": "2026-09-30"
}
```

`allow_formal` 只有在治理 manifest、二次复核决定和分组切分均通过后才可改为
`true`。正式快照必须钉住输入文件哈希、输出哈希、规则版本、来源/标签/类别
计数和隔离计数；回放时 `input_hashes` 必须非空、全部为规范小写 SHA-256，且
覆盖每个声明的必需/已存在 optional 源；缺失 optional 源必须逐项记录在
`missing_optional`。治理配置会在读取前拒绝空路径，以及跨 `sources`、`existing`、
`incoming` 的同文件重复、路径别名和符号链接别名；回放也会拒绝未知、多余或重复的
源路径。重新生成 manifest 不能掩盖替换样本或缩小分母。

## 训练集使用边界

训练集只接收 `train` 分区中已批准的请求级记录。`validation` 用于选择参数和
回归检查，`blind` 只用于最终独立验收；二者不得回灌训练、规则或特征选择。
白流量、已知攻击、变形攻击、业务滥用和 hard-negative 按来源分别统计，不用
未经验证的隔离记录凑比例。日志、PCAP、payload 和规则文本属于外围参考，必须
先在本地靶场转换成带完整 HTTP 上下文的记录，并记录生成脚本、种子、响应和
标签来源；没有这些信息时只能留在隔离区。

## 与评测平台的关系

治理后的完整请求集可以使用 `cmd/cheesewaf-corpus --mode split` 生成
`train`、`validation`、`blind` artifact。盲集只能通过带治理 manifest 和独立制品
哈希的 `--mode evaluate-split --evaluation-split blind` 入口回放，例如：

```bash
go run ./cmd/cheesewaf-corpus \
  --mode evaluate-split \
  --corpus /absolute/path/evaluation-split.json \
  --governance-manifest /absolute/path/manifest.json \
  --expected-artifact-sha256 <64-lowercase-sha256> \
  --evaluation-split blind \
  --output /absolute/path/blind-report.json
```

首次捕获可用 `make evaluation-lock` 生成不可覆盖的聚合锁记录；锁文件和完整
artifact 哈希必须复制到与输入目录分离的受控存储，不能把同一可写目录中的副本
当作独立证据。

不能把 raw corpus、日志或 catalog 条目直接交给 analyzer。日志、PCAP 和 payload 参考集即使许可
清晰，也只能在完成请求级转换、全局去重和二次复核后再决定是否成为正式输入。
