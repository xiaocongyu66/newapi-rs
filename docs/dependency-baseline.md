# P0 Rust 依赖基线

## 远程执行与锁文件回收记录

- 首次解析：run [41436159208](https://github.com/xiaocongyu66/newapi-rs/actions/runs/41436159208)，commit `92c05ba20d46b0ba2eb4297829686f75aee248bf`，attempt 1 success；独立审阅确认 resolve/check/export 成功，实际启用图无 MySQL/Moka。
- Cargo.lock 从该运行 artifact 原样回收，并提交至 `75fb5f5330ba1d95d264ef45485e4f5e61aa7ec9`。未本地生成或手工改写锁文件。
- 回收后的远程验证：run [41437057426](https://github.com/xiaocongyu66/newapi-rs/actions/runs/41437057426)，同一锁文件提交，结论 success；独立最终复核进行中，不据此宣称 P0 总体完成。
- 以下“本次未执行/尚无锁文件”是 Agent 首次交付时的历史状态；当前执行状态以上述精确运行记录为准。

## 边界与状态

2026-11-02：按主计划第 22 行批准的 P0 依赖解析建立独立探针。`tools/dependency-probe` 只有清单及最小 library target，不是服务、业务实现或 P1 验收；没有根 workspace、服务启动、数据库连接、迁移或测试。P1 再将锁定依赖纳入真实模块化 workspace，并重新远程验证。

最新用户决定覆盖最初三库要求：Rust 主库仅 SQLite + PostgreSQL，不支持 MySQL；清单不启用 SQLx `mysql`/`any`，后续 Rust 验证矩阵不要求 MySQL。历史 Go 基线与测试保持原样。ClickHouse 日志及 Timescale 扩展范围不因本次决定自动删除。保留原 schema 语义，不自动执行有损转换。

本次仅只读查询官方 registry/发布清单/源码，并编写文件；未执行本地 Cargo、构建、测试或脚本，未提交、推送或触发远程任务。尚无真实 Cargo.lock，不能称依赖图已冻结或编译已通过。

## 版本证据与选择

查询日期：2026-11-02。通过 HTTPS 只读读取 crates.io 官方 sparse index，筛选 `yanked = false` 且版本号无预发布后缀的稳定条目。以下是当次取得的版本，不使用浮动 `latest`/`stable` 作为构建输入。直接依赖用 `=版本` 固定；传递依赖由首次远程生成的 Cargo.lock 固定。清单特性基于 registry 的 `features`/`features2` 核对，完整可共存性仍必须以远程解析及检查为准。

| 依赖 | 选定版本 | registry 声明最低 Rust | 官方版本证据 |
| --- | --- | --- | --- |
| axum | 0.8.9 | 1.80 | https://index.crates.io/ax/um/axum |
| tokio | 1.54.1 | 1.85 | https://index.crates.io/to/ki/tokio |
| tower | 0.5.3 | 1.64.0 | https://index.crates.io/to/we/tower |
| tower-http | 0.7.1 | 1.65 | https://index.crates.io/to/we/tower-http |
| serde | 1.0.229 | 1.56 | https://index.crates.io/se/rd/serde |
| tracing | 0.1.44 | 1.65.0 | https://index.crates.io/tr/ac/tracing |
| tracing-subscriber | 0.3.23 | 1.65.0 | https://index.crates.io/tr/ac/tracing-subscriber |
| reqwest | 0.13.5 | 1.85.0 | https://index.crates.io/re/qw/reqwest |
| sqlx | 0.9.0 | 1.94.0 | https://index.crates.io/sq/lx/sqlx |

工具链固定 **Rust 1.99.1**，证据为 https://static.rust-lang.org/dist/channel-rust-stable.toml 的 `date = 2026-10-15`、`pkg.rust.version = 1.99.1 (58cf8f9c3 2026-10-13)`、完整发布 commit `58cf8f9c35b355199727627d07ae34a4e2846d67`。这高于所选直接依赖的已声明 MSRV；不代表已验证全部传递依赖。工作流使用 `rustup toolchain install 1.99.1 --profile minimal --no-self-update`，所有 Cargo 调用显式 `+1.99.1`；不依赖 runner 默认工具链。清单 `rust-version` 同样固定为该版本。

兼容性依据与最小特性：

- Axum 0.8.9 registry 要求 Tokio `^1.44`、Tower `^0.5.2`，所选版本满足该范围；启用 HTTP/1、HTTP/2、JSON 和 Tokio。
- Tower 负责 util/timeout/limit；Tower HTTP 负责 trace/CORS/request-id/limit。不同依赖可能带入其他 tower-http 版本；由远程 tree/metadata 展示，不能预先声称单版本收敛。
- Reqwest 0.13.5 的 TLS 特性名是 `rustls`，不沿用旧版 `rustls-tls`；禁用默认特性，启用 HTTP/2、JSON、流响应。代理、表单、多段上传等后续按实际接口扩展并重新锁定。
- SQLx 0.9.0 禁用默认特性，只启用 Tokio、Rustls AWS-LC、PostgreSQL、`sqlite-bundled`、JSON。与 Reqwest 默认 Rustls provider 路径一致，避免主动混入 ring provider；最终图仍待检查。
- `sqlite-bundled` 避免 SQLx 0.9 的 `sqlite` 聚合特性附带 load-extension/deserialize 等非必要能力。SQLite 是内嵌 C 库；远程 `check` 可能调用 C 工具链构建依赖，这是依赖验证而不是纯下载。所带 SQLite 版本待 Cargo.lock 和 metadata 确认。
- 不启用 SQLx query macros、migrate、Any；没有 DATABASE_URL，没有自动迁移。以后有需要时按阶段增加功能，不把本探针当完整服务特性清单。
- 用户已明确不采用 Moka；当前配置快照使用标准库 Arc/锁，不引入缓存淘汰语义，也不替代 Redis 的跨实例一致性职责。

## PostgreSQL 9.6 可行性与后续矩阵

官方发布版证据：

- https://github.com/launchbadge/sqlx/blob/v0.9.0/README.md
- https://github.com/launchbadge/sqlx/blob/v0.9.0/sqlx-postgres/src/connection/establish.rs

只读检查发现 SQLx 0.9.0 建连过程仍处理 MD5、明文密码和 SASL，使用 PostgreSQL Startup 消息和常规会话参数；该流程中未见硬编码拒绝 9.6 的版本下限。这仅支持“存在连接可行性”，**不能证明 PostgreSQL 9.6 已受支持**。README 未给出明确 9.6 保证；发布标签 README 中安装示例还保留 `0.8`，因此依赖实际版本与特性以 registry 为准，不盲从示例。

保留原 PostgreSQL 9.6 门槛，不默默提升。Rustls 仅支持 TLS 1.2/1.3；旧服务端证书、密码套件或 TLS 配置可能阻止连接，不通过关闭证书校验或降级安全配置掩盖失败。服务端认证、类型目录查询、SQL 方言和事务行为也可能在建连后暴露不兼容。若失败，记录准确错误与影响，先请求计划修订。

| 后续对象 | 必需证据 | 当前状态 |
| --- | --- | --- |
| PostgreSQL 9.6（隔离环境，不接生产） | 固定镜像摘要/服务端版本、握手与原认证、TLS、参数绑定、JSON/数值/时间/NULL、事务回滚、原 schema/options 读取 | 未验证；P1 实测 |
| PostgreSQL 当前部署版本 | 同上，避免仅旧版本连接成功就宣称全部兼容 | 未验证；P1 实测 |
| SQLite 原数据文件副本 | 实际 bundled 版本、原 schema/类型亲和性、JSON、锁与事务、options 读取、无自动建表或有损改写 | 未验证；P1 实测 |
| Timescale / ClickHouse 日志 | 按主计划记录扩展/日志协议及行为，不以本探针宣布兼容或删除 | 保留范围，另行验证 |

本工作流无数据库 service 容器，不运行数据库连通性探测或行为测试。原“三库 P1”要求已按最新明确决定收敛为两种主库，非静默删减。

## 远程工作流与证据

新增 `.github/workflows/p0-dependencies.yml`，不改既有 CI。标准 `ubuntu-24.04`、30 分钟超时、`contents: read`、同 ref 取消过期运行；不使用 `pull_request_target`，checkout 不持久化凭据。

Action 均固定完整 SHA：checkout/upload-artifact 复用现有 CI；cache 的 `v4` 引用通过 GitHub API 只读核对为 `0057852bfaa89a56745cba8c7296529d2fc39830`。只缓存 registry 下载与源码，不缓存 Cargo.lock 或 target。缓存不代替锁文件证据。

仅在 GitHub Actions 执行依赖相关 Cargo 操作：

1. 尚无锁文件时 `cargo +1.99.1 generate-lockfile`；回收锁文件存在时保留，不每次重新解析漂移。
2. `cargo +1.99.1 check --locked`。
3. `cargo +1.99.1 tree --locked`、`tree --locked --edges features`、`metadata --locked --format-version 1`。

不运行服务、cargo test/build/run、迁移或生产操作。check 失败不伪装成功；Bash pipefail 保留管道退出状态，存在锁文件时仍尝试导出图，always 上传证据。初始化/网络/安装失败可能没有锁文件；强制终止或 runner 故障也可能阻止上传，不承诺失败时必有完整产物。

artifact 名为 `p0-dependencies-<精确事件SHA>-<run_id>-<attempt>`，保留 14 天，包含实际 Cargo.lock（若成功生成）、清单和最小源码、工作流副本、event/checkout 精确 SHA、run/runner 信息、工具链版本、解析/检查日志、tree/features/metadata、步骤状态及 SHA256SUMS。PR 运行 SHA 是实际 checkout 的合并提交，不应误认为 PR head SHA。最终成功状态还需核对 GitHub run conclusion（证据快照在上传之前生成）。

## 远程验证与回收指令（待授权发布后执行）

本次不提交、不推送、不调用以下命令。由主代理/用户确认提交并推送至获授权仓库后执行，替换所有占位符：

```sh
gh workflow run p0-dependencies.yml --repo <OWNER/newapi-rs> --ref <BRANCH>
gh run list --repo <OWNER/newapi-rs> --workflow p0-dependencies.yml --branch <BRANCH> --limit 5
gh run watch <RUN_ID> --repo <OWNER/newapi-rs> --exit-status
gh run view <RUN_ID> --repo <OWNER/newapi-rs> --json headSha,event,status,conclusion,url
gh run download <RUN_ID> --repo <OWNER/newapi-rs> --name p0-dependencies-<SHA>-<RUN_ID>-<ATTEMPT> --dir /root/newapi-rs-p0-deps/dependency-evidence-<RUN_ID>
```

若 workflow_dispatch 尚未在默认分支注册，使用该新增工作流的路径匹配 push/PR 运行，不为此改既有 CI。下载前确认目标目录不存在、父目录是当前授权工作区。核对 artifact 的 SHA256SUMS、checkout SHA、清单内容和远程 run 成功结论；确认 check/resolve/export 均成功，核查 features 中实际启用的数据库驱动，而非仅凭 lockfile 是否包含可选包判断启用情况。然后将真实 Cargo.lock 原样回收到 `tools/dependency-probe/Cargo.lock`，记录 run URL、SHA 与校验和，并在纳入锁文件的新提交上再跑一次 `--locked` 工作流。不手工伪造或编辑 lockfile，不在本地运行 Cargo。

P0 依赖子项只有在真实产物回收和独立核对后才可标记通过；P0 总体与 P1 真实行为验收仍按主计划独立推进。
