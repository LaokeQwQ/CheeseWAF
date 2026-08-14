# 防护等级 0～5

现行口径见 [protection-policy-roadmap.md](protection-policy-roadmap.md)。本文说明仓库里怎么接。

2026-08-09 旧文按「0～4 + 置信度门槛」写，已经作废。现在按**形状 + 档位**决定拦不拦。

## 配置

站点字段：`waf.paranoia_level`（YAML / JSON / SQLite 列）。

- 合法值：0～5
- 省略或越界：按 3
- 写明 `0`：只记不拦，不会被改成 3

接入位置：

- `internal/config`：`WAFConfig.UnmarshalYAML`、`EffectiveParanoiaLevel`
- `internal/storage`：`sites.paranoia_level`，默认 3
- `internal/cli/service.go`：按站点创建 Analyzer
- 站点页：`paranoia_level` 下拉

## 拦不拦

`Analyzer.blockableHit`：

- 0～1：永不拦
- 2～5：完整形状（isolated）可拦
- 夹杂（embedded）只在 5 拦
- 2～5 共用同一证据门槛（语法 + 语义）；形状已经决定夹杂能不能拦

## 待确认

- 2～4 夹杂：放行，写入 `review_items`，后台问模型
- 5：当场拦，仍写入 `review_items`（状态 `blocked`），后台仍问模型
- 已拦截条目仍可一键加长期规则或指纹；不能改成放行

## 短时升 5

站点 `semantic_policy.promote_seconds`。仅 4 档夹杂命中后生效。截止时间写在 `site_promotes`，进程重启后读回。
