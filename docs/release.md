# 发布、升级与回滚

## 版本规则

正式版本使用 `vMAJOR.MINOR.PATCH` 标签，例如 `v1.2.0`。

`MAJOR` 表示不兼容的配置、数据库或 API 变化。`MINOR` 表示向后兼容的功能增加。`PATCH` 表示向后兼容的修复。

`dev`、`canary` 和 `master` 只用于开发、预览和稳定分支构建。它们不是正式版本标签。

## 发布正式版本

1. 确认 `dev` 的检查全部通过，并按项目分支规则逐级合入 `canary` 和 `master`。
2. 在 `master` 上创建并推送 `vMAJOR.MINOR.PATCH` 标签。
3. 标签工作流会运行 GoReleaser、生成各平台压缩包、`SHA256SUMS` 和软件物料清单。
4. 发布前核对工作流中的签名检查。没有签名凭证时，工作流必须失败，不得把未签名产物标成正式版本。
5. 发布后下载一个目标平台的压缩包，核对 `SHA256SUMS`，再执行启动冒烟测试。

正式版本的发布说明应记录数据库版本、配置兼容性和已知限制。不要用开发分支构建替代正式版本。

## 升级前备份

升级前停止写入，备份配置文件和 SQLite 数据库：

```bash
sudo systemctl stop cheesewaf
sudo install -d -m 750 /var/backups/cheesewaf
sudo cp -a /etc/cheesewaf /var/backups/cheesewaf/config-$(date -u +%Y%m%dT%H%M%SZ)
sudo cp -a /var/lib/cheesewaf/cheesewaf.db /var/backups/cheesewaf/cheesewaf-$(date -u +%Y%m%dT%H%M%SZ).db
```

备份完成后再替换二进制。启动新版本时，SQLite 会在事务内按 `PRAGMA user_version` 执行迁移。迁移失败会回滚本次数据库改动，服务不会继续使用不完整的数据库。

## 升级后检查

```bash
sudo systemctl start cheesewaf
curl --fail --cacert /etc/cheesewaf/ca.pem https://127.0.0.1:9443/api/health/ready
sudo journalctl -u cheesewaf -n 100 --no-pager
```

确认管理面可访问、站点配置数量正确、规则数量正确，并检查迁移错误。升级后不要删除旧备份。

## 回滚

如果新版本无法启动，先停止服务，再恢复同一时间点的二进制、配置和数据库备份。不要让旧版本打开已经由新版本升级过的数据库；如果数据库版本更高，旧版本会拒绝启动。

```bash
sudo systemctl stop cheesewaf
sudo cp -a /var/backups/cheesewaf/cheesewaf-YYYYMMDDTHHMMSSZ.db /var/lib/cheesewaf/cheesewaf.db
sudo rm -rf /etc/cheesewaf
sudo cp -a /var/backups/cheesewaf/config-YYYYMMDDTHHMMSSZ /etc/cheesewaf
sudo systemctl start cheesewaf
```

恢复后再次检查就绪接口和日志。保留失败版本的日志，便于定位迁移或配置兼容问题。
