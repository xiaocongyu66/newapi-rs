# P1 Rust 远程验证与集成交接

## P2 Redis session cache 增量（最新交接）

本次只修改 p1-rust.yml、p1-ci.py、p1-ci-test.py、本文；未本地执行任何测试、服务或容器，未提交推送。crypto oracle 包同步为 **internal/identity**，覆盖下文旧 common 约定，避免回归主集成修复。

- 2026-11-02 经 `gh api repos/docker-library/official-images/contents/library/redis` 只读核实官方 `7.2.17-bookworm`，amd64 支持，来源 `redis/docker-library-redis` commit `41bd5f7bdf101142b029865bf727a97810ca8e02` / tag `v7.2.17`。本机 registry auth 请求超时，**没有虚构已取得 digest**。prepare 扩展现有 registry 校验：固定此完整版本 tag，远程获取官方 library/redis manifest、校验 SHA256 和 linux/amd64，输出不可变 digest。验证失败即阻断；verify service 只用 `redis@sha256:...`，原始 manifest/tag/digest 存 prepare artifact。
- PG14/17 两个 job 各自拥有独立临时 Redis service，随机映射端口，无生产凭证、无外部 Redis、无共享持久卷。healthcheck 为 redis-cli ping。只在 verify 步骤注入 `TEST_REDIS_URL=redis://127.0.0.1:<job临时端口>/0`；TIME、Lua、CLIENT ID/KILL 使用测试专用实例的默认权限，不接生产服务。
- driver 缺 TEST_REDIS_URL 直接失败，输出日志前 add-mask；artifact 日志额外遮蔽完整环境 URL 及 redis/rediss URL。用容器内 redis-cli INFO server 验证实际版本必须恰为 7.2.17，记录真实退出码、版本判断、镜像 digest。INFO 不等于 Rust adapter 验证，后者见下一项。
- 已读取 `/root/newapi-rs-p2-auth/crates/identity/tests/session_cache.rs`，其四项测试名并不统一以 redis_ 开头，因此采用实际 binary：`cargo +1.99.1 test --locked -p newapi-identity --test session_cache -- --test-threads=1`，不加名称筛选。要求正执行数、failed=0、ignored=0；不存在 binary 或零测试直接失败。该 binary 也会随 workspace test 执行。
- 当前四项实际测试覆盖独立连接撤销拒绝迟到回填、Redis 自然 TTL 到期、版本/schema/白名单/截止时间、真实 WRONGTYPE 与 CLIENT ID/KILL 断连错误。临时 key 为随机 SID，清理仅限自身 key；不使用 FLUSHALL、不杀其他测试连接。运行时真实退出码、passed/failed/ignored/filtered 和版本证据入同 SHA/run/attempt artifact。
- 新增三个 CI 回归测试（URL 脱敏、精确 Redis 版本拒绝前缀误匹配、session_cache 命令构造），尚未运行。manifest 对直接 Redis 依赖要求 `=0.32.7`、default-features=false、features 恰为 tokio-comp/script。既有 MySQL/Moka 禁用和锁定版本保留。
- 根 lock 不自动漂移。主代理集成新依赖后仍须显式 `gh workflow run p1-rust.yml --ref migration/p2 -f refresh_lock=true`，回收/审阅/提交该精确 run 的真实 lock，再对新 SHA locked 重跑。Redis tag/digest 的远程可拉取性及所有新增行为仍待 Actions 验证。

## P2 共享 Go oracle 增量

新增 `prepare → oracle → verify(pg14, pg17)` 依赖链；原 P1 process job 保持。oracle job 仅构建一次两个 Go 包，固定上游 SHA `17970da4571e81308f176a0e61a38276e5771606`，注入模板到 RUNNER_TEMP 副本，不修改上游 checkout 或生产 crate。仍使用 P0 固定 checkout/setup-go/upload/download SHA、contents:read。

实际已读取 Origin 作者模板：包 `internal/security`、测试 `TestP2OriginOracle`，通过 `t.Logf("P2_ORIGIN_ORACLE %s", ...)` 输出真实调用结果。CI 从 `go test -json` Output 事件抽取前缀后的对象，每行一个 JSON，**不转成数组、不使用模板的手写 Allowed 值替代实际结果**。Rust `P2_ORIGIN_ORACLE_PATH` 指向该 JSONL。每个 verify job 在 workspace test 外另执行 `cargo test --locked -p newapi-security --test origin_oracle origin_matches_go_oracle -- --exact` 并要求正测试数；至少40条、唯一名称及关键case由该 Rust 测试检查。

crypto 模板在本次读取时尚未出现在主集成目录，且 SendMessage 未在工具注册表提供，不能声称已与作者直接确认。当前接线约定为 `internal/common` 包、模板中唯一 `TestP2*Oracle*` 入口（从实际文本提取，不猜测名称以免零执行假绿），输出二选一：直接写入 `P2_CRYPTO_ORACLE_PATH` 指定文件（JSON 或 JSONL，保持原字节），或日志 `P2_CRYPTO_ORACLE <JSON>`（抽取为 JSONL）。同时写文件与 marker 会拒绝。主代理须转告 crypto 作者确认此接口；若实际模板采用另一 env/包/格式，必须在远程触发前对齐，不能跳过 oracle。

Go 两命令保存真实退出码、顶层 pass、子测试 pass/fail/skip、原始事件、模板和 fixture；任一失败、skip、空文件、无顶层通过即 job 失败。artifact `p2-oracle-<SHA>-<run>-<attempt>` 经 always seal/upload 保留。verify 下载同一 artifact，核对 SHA/run/attempt、上游身份、执行成功记录及 fixture SHA256，然后通过 GITHUB_ENV 为所有后续 Cargo 测试注入 `P2_CRYPTO_ORACLE_PATH` 与 `P2_ORIGIN_ORACLE_PATH`。verify 再检查两路径必须存在非空，缺失不 skip。两个矩阵不重复 Go 编译。

工作流路径过滤新增 `scripts/ci/p2-*`。本次仅编辑 `p1-rust.yml`、`p1-ci.py`、本文，未编辑作者模板；未本地执行任何代码或测试，新增流程仍待远程验证。若 security 新 dev 依赖导致 lock 过期，必须遵循下述显式 refresh/回收/locked 重跑流程，不在普通 job 自动更新。

## P2 首批 CI 增量（最新约定，覆盖下文 P1 历史描述）

主代理已确认 P1 PASS，进入 migration/p2。本次仅修改 workflow、CI driver、driver tests 和本文，未修改生产 crate，未本地运行任何测试。本次新增 CI 尚待远程验证。

- manifest 白名单现在恰为 `crates/config`、`crates/storage`、`crates/catalog`、`crates/identity`、`crates/security`、`apps/server` 六个成员，probe 继续排除。既有探针精确版本、SQLx defaults/MySQL/Moka 禁用保持。
- 两个 PG job 各追加 `newapi-identity` 的 `sqlite_` / `postgres_` 筛选测试，分别要求 passed > 0、failed = ignored = 0；模块所有者须采用对应命名和真实数据库。纯 crypto/security 测试随 `cargo test --locked --workspace` 执行。
- `workflow_dispatch.inputs.refresh_lock` 为布尔值，默认 false。仅事件为 workflow_dispatch 且输入 true 才允许 root lock 更新：存在则 `cargo +1.99.1 update`，不存在则 `generate-lockfile`。普通 push/PR/默认 dispatch 一律不重新解析 lock，缺锁直接失败；过期锁由后续 `metadata --locked` 拒绝，不自动漂移。
- 显式 refresh 记录原 lock SHA256、真实命令退出码、`refreshed: true` 与 `requires_recovery_and_locked_rerun: true`；现有 artifact 名仍精确绑定 SHA/run/attempt。下游仅在同一授权 dispatch 中允许 prepared lock 与 committed lock 不同，并验证原锁 SHA256。普通运行仍拒绝任何差异。
- `cargo update` 可能更新允许范围内的传递依赖，须审阅 lock diff、features/metadata 与许可证；既有直接依赖仍被探针精确版本限制。新 crypto 依赖的固定版本由主代理清单审阅负责。
- driver 新增三项回归测试：push 即使带环境标志也不得更新；默认 dispatch 锁定；显式 dispatch 对存在/缺失 lock 分别选择 update/generate。连同原五项共八项，仅 Actions 执行。

### 首次远程更新操作（主代理执行，本代理未触发）

先集成六模块清单及本次 CI 文件到 `migration/p2`，提交并推送新仓库。普通 push 如因旧 lock 失败是预期门禁，不应删除 `--locked`。

```sh
gh workflow run p1-rust.yml --ref migration/p2 -f refresh_lock=true
```

需保证 workflow_dispatch 工作流已存在于默认分支；若该分支本身是默认分支则无额外步骤。若 GitHub 尚未注册该 workflow，先经授权将调度定义同步到默认分支，不能用本地 Cargo 绕过。

从该精确 run/attempt 的 `p1-prepare-<SHA>-<run>-<attempt>` 下载 Cargo.lock 和 SHA256SUMS，核实 source identity、checksum、依赖变更后，将真实 root lock 提交到 migration/p2。再以新 SHA 的普通 push，或 `gh workflow run p1-rust.yml --ref migration/p2 -f refresh_lock=false` 完整 locked 重跑。refresh run 即使绿也只是待回收证据，不可替代该 locked 重跑及独立 verification。不要同时推送新提交取消正在回收的 refresh run。

## 状态与边界（P1 历史记录）

本交付仅实现 P1 CI 编排、证据驱动脚本及脚本回归测试，**尚未运行，不能判定 P1 PASS**。未本地执行构建、测试、自写脚本、服务或容器；未提交或推送。P0 工作流未修改。业务 Rust 与模块测试由各模块所有者提供；本文件不替代主计划或独立 verification。

交付文件：`.github/workflows/p1-rust.yml`、`scripts/ci/p1-ci.py`、`scripts/ci/p1-ci-test.py`、`scripts/ci/p1-process.py`、`scripts/ci/p1-go-fixture_test.go.txt`、本文。只使用标准 `ubuntu-24.04`、`contents: read`、超时、取消同分支过期运行、注册表下载缓存；没有 `continue-on-error`，两个数据库 job 不互相 fail-fast。

## 固定基线与只读镜像核实

- Rust 固定 `1.99.1`，安装 rustfmt/clippy；依赖版本从 `tools/dependency-probe/Cargo.toml` 精确比较，不以 semver 范围替代。根 workspace 成员必须恰为 config/storage/catalog/server 四个路径，并显式排除探针。禁止直接 Moka/sqlx-mysql、SQLx default features/MySQL；完整解析特性另存 artifact，仍需独立审阅传递依赖及特性闭包。
- checkout/cache/upload-artifact 的 SHA 原样沿用 P0 probe 工作流。新增 download-artifact v4.3.0 经 `gh api repos/actions/download-artifact/git/ref/tags/v4.3.0` 只读核实，SHA 为 `d3f86a106a0bac45b974a628896c90dbdf5c8093`。
- 2026-11-02 经 GitHub 官方 `docker-library/official-images` 的 `library/postgres` 核实 `17` tag 及 amd64 定义；9.6 官方历史与 EOL 删除记录见 `docker-library/postgres` commit `36abfddd6f7235770d00f8546b199936b0ca77aa`。2026-11-05 用户将最低版本门槛修订为 14，矩阵改用 `14` tag。**这只能证明官方来源，不能证明镜像当前可拉取。**
- 本机只读请求 Docker Hub / auth.docker.io 失败，未宣称取得 manifest/digest。工作流 prepare 必须先向官方 registry 只读取得 `library/postgres:14` 与 `:17` 的 manifest，校验内容 SHA256、linux/amd64 存在，并输出不可变 digest；服务 job 仅使用这些 digest。任一标签不存在、限流或网络失败立即红灯，不回退到更高版本、不跳过 14。
- 实际服务启动后由容器内 `psql SHOW server_version` 核验 14/17 主版本并保存结果。镜像可用不等于 SQLx 0.9.0 已兼容 PostgreSQL 14；后者必须由 Rust 测试实证。

官方只读来源：

- https://github.com/docker-library/official-images/blob/master/library/postgres
- https://github.com/docker-library/postgres/commit/36abfddd6f7235770d00f8546b199936b0ca77aa
- https://api.github.com/repos/actions/download-artifact/git/ref/tags/v4.3.0

## 工作流行为

1. 检出精确事件 SHA（PR 为事件的 merge SHA，不混称 head SHA），保存 SHA、run ID、attempt、runner image、toolchain、工作流和清单。
2. 根 `Cargo.lock` 存在则保留，缺失时才远程 `cargo +1.99.1 generate-lockfile`。生成失败不伪造 lock。保存根 lock、完整 locked metadata、依赖树、features、清单、校验和。
3. 下游下载**同 SHA/run/attempt** 的 prepare artifact，核对 identity、lock SHA256；若仓库已有 lock，再比对字节一致性，不覆盖不同的已提交 lock。
4. PostgreSQL 14 与 17 两个 job 均运行：
   - `cargo +1.99.1 check --locked --workspace`
   - `cargo +1.99.1 fmt --all --check`
   - `cargo +1.99.1 clippy --locked --workspace --all-targets -- -D warnings`
   - `cargo +1.99.1 test --locked --workspace`
   - 完整 locked metadata / features 导出。
5. 每个 job 另对 `newapi-storage`、`newapi-catalog` 分别运行 `cargo test --locked -p <package> sqlite_ -- --test-threads=1` 和对应 `postgres_`。每个命令必须至少一条 passed、零 failed、零 ignored；workspace 测试也禁止 ignored。filtered 单独记录，不能当执行数。
6. 单条命令失败后仍收集后续命令证据，但整个 driver 最终返回非零，不能因最后一条成功变绿。日志记录真实退出码、耗时、测试统计、策略判断。异常类型单独记录，避免异常字符串含 DSN。未执行命令明确记录 not-executed，不伪装 exit 0。
7. always 步骤保存 steps/job status、root lock 和 SHA256SUMS，失败也上传 artifact（14 天）。artifact 名绑定 SHA、run ID、attempt 和 backend。runner 被强制终止、取消或 service 在步骤开始前拉取失败时，Actions 无法保证上传；这种情况以平台失败日志为证据，绝不算通过。

### 首次 lock 回收门禁

首次缺失 lock 的远程成功仅是 bootstrap 证据，**不能验收 P1**。`lock-status.json` 明确 `requires_recovery_and_locked_rerun: true`。集成者须经授权从该精确 run/attempt 下载根 lock、校验 SHA256、检查 metadata 和许可证，然后提交真实产物；不得手写或复制探针 lock 冒充根 lock。提交后必须对新精确 SHA 重跑本工作流，确认 `generated: false`、两个数据库 job 成功，再交独立 verification。CI 不自动提交，不修改 GitHub 仓库内容。

## 模块所有者必须满足的测试接口

以下是 CI 与并行 Rust 实现的集成契约，不表示业务代码已具备：

- package 名为 `newapi-storage`、`newapi-catalog`。**真实数据库测试名称必须分别含 `sqlite_` / `postgres_`**。没有匹配测试会因 passed=0 红灯，而不是静默通过；集成者可统一测试命名，但不得删去正计数门禁。
- `TEST_POSTGRES_DSN` 仅在 verify 步骤注入 job 临时容器的 `p1_test` 专用库，没有生产 secret。`P1_REQUIRE_POSTGRES=1` 表示缺少 DSN/连接失败必须 fail，禁止 Rust 测试 `return` 冒充通过、禁止 `#[ignore]`。测试应从环境取 DSN，不将其写入 panic/assert/Debug；CI 额外遮蔽完整 DSN 与 PostgreSQL URL，不把遮蔽当作业务日志安全测试的替代。
- PostgreSQL 测试使用**单连接池（max_connections=1）及连接私有临时表 pg_temp.options**；fixture 与被测查询必须复用该连接，search_path 将 pg_temp 置前。临时表随连接关闭销毁，不创建永久 schema、不 drop database、不改 public schema、不共享全局 options。测试不能因重建连接使临时表丢失而偷偷回退到 public.options。
- SQLite 测试用唯一临时文件，fixture 在调用 `Database::connect` 前创建必要表；另测不存在文件不得自动创建、缺表加载失败、禁止 MySQL DSN、正常关闭。不能用 mock 代替真实 SQLite。
- catalog 两库测试覆盖五个大小写精确 key、空值/空白/Unicode、未知 key 隔离、缺行保留 previous、删行保留 previous、首次空值、整体查询失败不发布部分快照。PostgreSQL 必须真实连接临时库；仅测试名字叫 postgres 不构成证据。
- server 自有测试随 workspace 运行，验证首次 load 失败不 listen、内存 GET envelope、全量快照发布、失败保留快照且 not-ready、非法配置/未实现路由/错误方法/优雅退出。CI 不能替模块编写这些 Rust 测试，也不通过修改 storage/server 规避编译错误。

解析 libtest 汇总能拒绝零执行和 ignored，但无法识别测试内部人为提前 return、mock 冒充真库或没有断言。独立 verification 必须对照上述模块测试源码和至少 2–3 条原始命令日志，不得只看绿灯。新增独立 process job 的真实 HTTP 进程 smoke，详见下节；该新增验证尚未运行，不能宣称通过。

## 追加：固定 Go oracle 与真实 Rust 进程差分

`process` 是单独 job（不在 PG 矩阵重复 Go 构建），仍依赖 prepare 的精确 lock 及身份/校验和核验。新增 `scripts/ci/p1-process.py`、`scripts/ci/p1-go-fixture_test.go.txt`；只在 GitHub-hosted Actions 执行。

1. checkout 固定 Go 上游 `17970da4571e81308f176a0e61a38276e5771606`，验证 SHA；复制到 RUNNER_TEMP，只有临时副本注入测试及 embed placeholder。setup-go SHA 和上游 build tags 沿用 P0，Go 依赖只读。
2. `go test -json -count=1 ... -run '^TestP1ExportPublicConfig$'` 实际调用五个现有 handler（Fiber synthetic context），保存每次真实状态码与 JSON body；不手写 expected envelope。覆盖 missing、empty、whitespace、Unicode、Markdown、HTML、URL 共七组输入，35 条响应。Go 测试必须恰好一条通过、零失败、零跳过，否则阻断。
3. fixture 同时携带输入 options 与上游 SHA。Python sqlite3 为每组创建独立临时文件及旧 options 表，用参数绑定装入同组输入，另加未知私密 key 的日志 canary。`cargo +1.99.1 build --locked -p newapi-server --bin newapi-server` 后启动真实二进制，以 SQL_DSN 指向该文件，PORT 使用内核分配的随机空闲端口；仅请求 127.0.0.1，无生产库或网络目标。
4. 对真实 HTTP 五 GET 的状态/JSON 逐项比较 Go oracle，**不是两份手写 expected**。每组发送 SIGTERM，要求十秒内退出码 0、端口关闭。两组负向进程测试为 SQLite 文件存在但没有 options 表、带 canary 凭证的非法 MySQL DSN；要求二十秒内非零退出且观察期间不监听。
5. 每个进程保留退出码、HTTP 检查数、失败类别、日志泄露判断；检查日志不得含 SQL_DSN、未知私密值及非法 DSN 用户名/密码 canary。原始日志先检查再脱敏落盘，防止失败 artifact 泄露敏感值。全部九组通过且 HTTP 检查数恰为 35 才成功；不忽略失败，finally 强制清理残留进程。轮询只发生远程进程启动测试，不在开发机运行。
6. artifact `p1-process-<SHA>-<run>-<attempt>` 包含 Go fixture、Go 原始测试事件、命令退出码/计数、root lock、Rust build 日志和每组进程结果；always seal/upload 保留失败证据。未执行项目仍标 not-executed。

范围说明：这是 Go **handler** 对 Rust **真实 HTTP 进程** 的差分；不声称启动了完整 Go 服务或验证 Go DB loader/完整中间件。随机端口分配与 bind 之间有极短竞争窗口，遇占用应红灯排查而非换端口掩盖失败。负向 no-listen 采用高频 TCP 观察并结合非零启动退出，不替代 server 单元测试的启动顺序断言。追加脚本/工作流尚未远程执行；catalog 编译/fmt 由其他所有者修复，不在此改动。

## 本次编写的 CI 回归测试

`p1-ci-test.py` 含五个 unittest：多 test binary 汇总（含失败/ignored/filtered）、零测试与编译失败不作正证据、环境秘密遮蔽、非预期 PostgreSQL URL 遮蔽、固定工具链和 locked 参数构造。仅由 Actions 调用；驱动和回归入口拒绝非 GitHub-hosted Actions 环境。未本地运行，尚无通过数。

## 尚待集成/验证的风险

- 本工作区没有 P1 Rust workspace 文件。主代理需集成其他所有者交付后才能运行；测试命名接口必须同步确认。
- 模块新增未在探针中的依赖需单独审阅固定版本；manifest 静态约束不是传递依赖审计的替代。
- 主代理报告首轮 run `41444440734` 已真实启动 PostgreSQL 9.6/17；本代理未据此宣称 Rust 测试通过。后续镜像拉取失败仍须报告受阻，不能默默抬高最低支持版本。
- 首次 bootstrap lock 必须回收提交并 locked 重跑；工具链/依赖可获得性、YAML 展开、脚本测试、Rust 编译和两库行为全部尚待 Actions 验证。
