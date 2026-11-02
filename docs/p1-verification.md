# P1 Rust 远程验证与集成交接

## 状态与边界

本交付仅实现 P1 CI 编排、证据驱动脚本及脚本回归测试，**尚未运行，不能判定 P1 PASS**。未本地执行构建、测试、自写脚本、服务或容器；未提交或推送。P0 工作流未修改。业务 Rust 与模块测试由各模块所有者提供；本文件不替代主计划或独立 verification。

交付文件：`.github/workflows/p1-rust.yml`、`scripts/ci/p1-ci.py`、`scripts/ci/p1-ci-test.py`、`scripts/ci/p1-process.py`、`scripts/ci/p1-go-fixture_test.go.txt`、本文。只使用标准 `ubuntu-24.04`、`contents: read`、超时、取消同分支过期运行、注册表下载缓存；没有 `continue-on-error`，两个数据库 job 不互相 fail-fast。

## 固定基线与只读镜像核实

- Rust 固定 `1.99.1`，安装 rustfmt/clippy；依赖版本从 `tools/dependency-probe/Cargo.toml` 精确比较，不以 semver 范围替代。根 workspace 成员必须恰为 config/storage/catalog/server 四个路径，并显式排除探针。禁止直接 Moka/sqlx-mysql、SQLx default features/MySQL；完整解析特性另存 artifact，仍需独立审阅传递依赖及特性闭包。
- checkout/cache/upload-artifact 的 SHA 原样沿用 P0 probe 工作流。新增 download-artifact v4.3.0 经 `gh api repos/actions/download-artifact/git/ref/tags/v4.3.0` 只读核实，SHA 为 `d3f86a106a0bac45b974a628896c90dbdf5c8093`。
- 2026-11-02 经 GitHub 官方 `docker-library/official-images` 的 `library/postgres` 核实 `17` tag 及 amd64 定义；经 `docker-library/postgres` 的 commit `36abfddd6f7235770d00f8546b199936b0ca77aa` 核实 9.6 官方历史与 EOL 删除记录。**这只能证明官方来源，不能证明旧镜像当前可拉取。**
- 本机只读请求 Docker Hub / auth.docker.io 失败，未宣称取得 manifest/digest。工作流 prepare 必须先向官方 registry 只读取得 `library/postgres:9.6` 与 `:17` 的 manifest，校验内容 SHA256、linux/amd64 存在，并输出不可变 digest；服务 job 仅使用这些 digest。任一标签不存在、限流或网络失败立即红灯，不回退到更高版本、不跳过 9.6。
- 实际服务启动后由容器内 `psql SHOW server_version` 核验 9.6/17 主版本并保存结果。镜像可用不等于 SQLx 0.9.0 已兼容 PostgreSQL 9.6；后者必须由 Rust 测试实证。

官方只读来源：

- https://github.com/docker-library/official-images/blob/master/library/postgres
- https://github.com/docker-library/postgres/commit/36abfddd6f7235770d00f8546b199936b0ca77aa
- https://api.github.com/repos/actions/download-artifact/git/ref/tags/v4.3.0

## 工作流行为

1. 检出精确事件 SHA（PR 为事件的 merge SHA，不混称 head SHA），保存 SHA、run ID、attempt、runner image、toolchain、工作流和清单。
2. 根 `Cargo.lock` 存在则保留，缺失时才远程 `cargo +1.99.1 generate-lockfile`。生成失败不伪造 lock。保存根 lock、完整 locked metadata、依赖树、features、清单、校验和。
3. 下游下载**同 SHA/run/attempt** 的 prepare artifact，核对 identity、lock SHA256；若仓库已有 lock，再比对字节一致性，不覆盖不同的已提交 lock。
4. PostgreSQL 9.6 与 17 两个 job 均运行：
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
