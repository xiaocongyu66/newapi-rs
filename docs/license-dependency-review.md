# P0 许可证、依赖与数据库边界复核

日期：2026-11-02。状态：进行中，非法律意见、非发布授权或P0验收。固定上游 `17970da4571e81308f176a0e61a38276e5771606`。本次只读源码、GitHub API；未执行第三方代码、本地构建或测试。事实=直接读取证据；推断=工程结论；待验证=尚无充分证据。本文补充而不改写主计划及上游法律文件。

## 1. go-epay v0.0.4：原始证据不能支持“维护者自有即可复用”

- **事实（上游声称）**：`/root/newapi/THIRD-PARTY-LICENSES.md:23,315–317` 标为 Proprietary/Internal、owned by project maintainer，并将其排除在第三方开源依赖审查外。这只是上游声明，不是给新仓库的授权文本。
- **事实（锁定版本）**：`/root/newapi/apps/api/go.mod:141` 为 `github.com/Calcium-Ion/go-epay v0.0.4`；`go.sum:9–10` 的模块校验和为 `h1:C96M7WfRLadcIVscWzwLiYs8etI1wrDmtFMuK2zP22A=`，go.mod 校验和为 `h1:cxo/ZOg8ClvE3VAnCmEzbuyAZINSq7kFEN9oHj5WQ2U=`。校验和不是许可证。
- **事实（原始GitHub查询）**：`gh api repos/Calcium-Ion/go-epay/git/ref/tags/v0.0.4` 返回 commit `d8c8810761402e9de0320c4b7eed3cfd7fa94461`（不是annotated tag）。对该SHA递归树查询返回 `truncated:false`，全集仅 `.github/workflows/go.yml`、`epay/{client.go,order.go,util.go,util_test.go}`、`examples/main.go`、`go.mod`、`go.sum` 及目录；**没有独立LICENSE/COPYING/NOTICE或README文件**。
- **事实**：通过contents API读取该SHA的 `epay/client.go`、`order.go`、`util.go` 及 `go.mod`，未见授权声明；`order.go` 指向支付协议文档，但协议链接本身不是SDK授权。本轮没有把未阅读测试/示例内是否存在声明说成已排除。
- **推断**：当前公开固定版本证据不足以确认新仓库可以复制/翻译SDK或再分发其产物。不能据此断言“无授权”，也不能因公开GitHub、上游AGPL、维护者身份相似便推定“已授权”。未发现独立许可证不等于证明不存在单独授权。
- **待验证/用户决策 L-EPAY**：维护者确认权利主体、固定版本、复制/修改/网络服务/再分发范围及可保存授权证据；或批准基于可合法使用的协议资料独立实现并保留全部支付能力。后者也需审阅素材来源，不能自动称为clean-room。不得以删支付缩范围。授权不清时暂不向新仓库复制SDK/测试素材、不发布相关二进制；P1纯配置切片不必链接此SDK，但P0必须记录处理责任及决策，不能把许可疑点宣告关闭。

原始证据链接：
- https://github.com/Calcium-Ion/go-epay/tree/d8c8810761402e9de0320c4b7eed3cfd7fa94461
- https://api.github.com/repos/Calcium-Ion/go-epay/git/trees/d8c8810761402e9de0320c4b7eed3cfd7fa94461?recursive=1

## 2. sing-box：实际为进程内路径，不是已证实隔离进程

- **事实（文档矛盾）**：`THIRD-PARTY-LICENSES.md:148–150` 声称 isolated egress process boundary、合规TODO。
- **事实（源码）**：`/root/newapi/apps/api/internal/egress/dial_singbox.go:14–18,23–75` 直接导入sing-box/sing，持有 `*box.Box`，调用 `box.New`、`instance.Start()`，将出站 `DialContext` 包为Go拨号器；文件头无build constraint。`register_dialer.go`直接注册协议。`main.go:87–88` 的 `defer egress.CloseSingBoxDialer()` 是**退出时关闭**，不是启动时禁用。`build_client.go`使用该拨号路径。此证据纠正对“关闭”的可能误读。
- **推断**：普通源码路径使用进程内库链接；不能拿“隔离进程”作为合规前提。是否某特定发布产物包含全部相关符号，仍须远程构建元数据/依赖图证明；未配置代理不等于未链接。不能通过保留Go sidecar冒充最终Rust重写。
- **事实（实际版本）**：go.mod/go.sum锁定 sing-box **v1.14.4**，sing **v0.9.7-0.20261023115459-5dc452e537bf**；上游清单仍是v1.12.12/v0.7.13。GitHub标签v1.14.4解析为 `c005f35300ce76427dc285481ec5695f5b179cd2`。该SHA的LICENSE写明Copyright 2022 nekohasekai、GPL version 3 or later，另有不得未经同意使用名称或暗示关联的文字；不能仅以旧表中的GPL-3.0覆盖这些细节。sing自身固定提交及所有传递依赖许可尚待逐项复核。
- **事实/推断**：本项目AGPL正文第13条明确涉及与GPLv3组合，并非见到GPL+AGPL就能断言不兼容。具体文件、附加文字、对应源代码与分发方式仍需合规审阅，不在此作确定法律结论。
- **待验证/用户决策 L-EGRESS**：确认保留协议能力的Rust实现路径、来源与发行义务；如选外部进程或调整支持能力，属于主计划技术/范围变更，必须用户审批。P1不实现该路径，最终产物合规与协议兼容在P6/P8/P9验收，不能预先削除功能。

原始许可：https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/LICENSE

## 3. 数据库：上游事实与目标范围

2026-11-02 用户明确取消 MySQL 支持。以下 MySQL 为上游历史事实，不纳入 Rust 实现、最低版本门禁或 CI。目标主库仅 SQLite/PostgreSQL；ClickHouse 日志和 Timescale 扩展继续列入对应后续阶段，不因本次调整删除。

| 项目 | 事实（固定源码） | 推断与待验证 |
|---|---|---|
| ClickHouse | `open_db.go:63–72`明确拒绝主库ClickHouse，仅`LOG_SQL_DSN`日志库可用；`:232–329`自建MergeTree、分区/排序及TTL同步；`usage/store_log.go:37–50,909–918`有LIKE方言、排序和显示ID专门路径 | 不是仅有未使用依赖，也不是通用主库支持；Rust需独立usage日志repository/驱动，不可假设SQLx三库覆盖它；待实测写入、过滤、分页/显示ID、TTL增加/移除与跨库查询边界 |
| TimescaleDB | `timescale_log.go:25–49`要求开关及PG日志库，扩展不可用时继续普通logs；创建扩展失败等则返回错误；`:52–105`扩大主键为(created_at,id)、create_hypertable、integer_now；压缩/保留策略默认关闭；`open_db.go:148–159`共享主库也可进入此路径 | 是PG日志扩展，不是独立主库种类；不能把关闭开关/扩展缺失的“成功”当hypertable通过。主从、共享/独立日志库、已有数据、权限失败、压缩/保留需专门矩阵；不能在P1连接时自动改旧库 |
| MySQL/PG | `README.md:264`、`apps/api/README.md:20`声明MySQL≥5.7.8、PG≥9.6 | 只是兼容承诺，不是此次验证结果；不得因为新驱动或现代镜像而静默提高最低版本 |
| SQLite/部署示例 | go.mod使用modernc.org/sqlite v1.40.1（Go模块版本）；`deploy/docker-compose.yml:107`注释示例ClickHouse24.8；data台账引用PG18、Timescale2.29.2-pg18 | 模块版本不等于SQLite引擎最低版本，部署示例不等于ClickHouse/Timescale最低版本；这些最低版本及PG/扩展配对待确认 |

**事实**：ClickHouse实际依赖为clickhouse-go/v2 v2.48.0、gorm driver v0.7.0，不是上游许可证摘要的v2.32.0/v0.6.0。依赖清单明显漂移，须以当前manifest/lock及实际产物重建。

**用户决策 D-SCOPE**：确认ClickHouse日志与Timescale日志扩展纳入完整兼容范围和阶段（建议按已有数据台账P7/P8），固定测试版本、最低版本验证办法及普通PG降级语义。此为提请确认，不是本文自行修订主计划。P1只实现获批的SQLite/PostgreSQL两类主库连接/options，后期日志实现不应强塞到P1，也不得悄悄取消。历史版本无法获取或SQLx不兼容时保持受阻，只有用户能批准替代证据或范围/版本变更。

## 4. 通用许可证义务与后期风险

- **事实**：`/root/newapi/LICENSE`是AGPLv3正文；`NOTICE:9–25`要求保留UI署名“Frontend design and development by New API contributors.”及 https://github.com/QuantumNous/new-api 链接、标记修改；`:33–50`有发行携带NOTICE及Apache依赖通知。换语言/新建仓库不自动消除来源义务。
- **待验证（P0）**：对将复制的前端/fixture/法律文件逐项登记来源，固定文件文本比对；维护者确认许可证处理路线。仅复制三份法律文件不等于完成全量审计。
- **待验证（后期，不单独阻止无相关素材的P1）**：全量Go/npm/Rust传递依赖SBOM、字体OFL原文/保留名、MPL与双许可选择、对应源代码入口、实际UI署名、镜像/二进制/bundle携带通知，在P8/P9关闭。当前无Rust lock，不能宣称已有清单覆盖Rust。

## 5. 远程复核交接（未在本地执行）

1. 在Actions固定checkout上游SHA，保存go env、go list -m -json all、go list -deps及构建标签；对实际构建产物记录go version -m等元数据。只上传脱敏依赖/许可证证据，不发生产数据。
2. 固定epay标签SHA并与Go模块zip/校验和来源对照；读取完整版本文件内声明，保存授权证据索引。GitHub树核查不替代权利主体确认。
3. 对sing/sing-box和实际Go/npm/Cargo依赖采集固定版本法律文本，记录来源、hash、选用条款和未决项；最终由维护者/必要的专业顾问审阅。
4. 新增数据库证据任务应由集成者另行评审，保留已通过基线CI；仅Actions临时隔离数据库、模拟器，禁止生产DSN或真实支付。记录server/extension/driver版本、连接成功证据、测试/跳过数及退出码。远程成功也不等于授权证明。
