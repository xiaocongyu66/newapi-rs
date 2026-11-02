# P1 Rust 远程验证与集成交接

## 状态与边界

本交付仅实现 P1 CI 编排、证据驱动脚本及脚本回归测试，**尚未运行，不能判定 P1 PASS**。未本地执行构建、测试、自写脚本、服务或容器；未提交或推送。P0 工作流未修改。业务 Rust 与模块测试由各模块所有者提供；本文件不替代主计划或独立 verification。

新增文件：`.github/workflows/p1-rust.yml`、`scripts/ci/p1-ci.py`、`scripts/ci/p1-ci-test.py`、本文。只使用标准 `ubuntu-24.04`、`contents: read`、超时、取消同分支过期运行、注册表下载缓存；没有 `continue-on-error`，两个数据库 job 不互相 fail-fast。

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
- PostgreSQL 每个测试创建**自己的唯一 schema**（不依赖新 PostgreSQL 特有函数），所有池连接均设置对应 search_path；fixture 创建旧 `options` 表并绑定参数。只清理自身 schema，不 drop database、不改 public schema，不共享全局 options。失败清理可以由整个临时 service 销毁兜底。
- SQLite 测试用唯一临时文件，fixture 在调用 `Database::connect` 前创建必要表；另测不存在文件不得自动创建、缺表加载失败、禁止 MySQL DSN、正常关闭。不能用 mock 代替真实 SQLite。
- catalog 两库测试覆盖五个大小写精确 key、空值/空白/Unicode、未知 key 隔离、缺行保留 previous、删行保留 previous、首次空值、整体查询失败不发布部分快照。PostgreSQL 必须真实连接临时库；仅测试名字叫 postgres 不构成证据。
- server 自有测试随 workspace 运行，验证首次 load 失败不 listen、内存 GET envelope、全量快照发布、失败保留快照且 not-ready、非法配置/未实现路由/错误方法/优雅退出。CI 不能替模块编写这些 Rust 测试，也不通过修改 storage/server 规避编译错误。

解析 libtest 汇总能拒绝零执行和 ignored，但无法识别测试内部人为提前 return、mock 冒充真库或没有断言。独立 verification 必须对照上述模块测试源码和至少 2–3 条原始命令日志，不得只看绿灯。本轮不增加 HTTP 进程 smoke（可选）；不得宣称已覆盖真实 server 端口 3001、SQL_DSN 启动与退出的进程级行为。

## 本次编写的 CI 回归测试

`p1-ci-test.py` 含五个 unittest：多 test binary 汇总（含失败/ignored/filtered）、零测试与编译失败不作正证据、环境秘密遮蔽、非预期 PostgreSQL URL 遮蔽、固定工具链和 locked 参数构造。仅由 Actions 调用；驱动和回归入口拒绝非 GitHub-hosted Actions 环境。未本地运行，尚无通过数。

## 尚待集成/验证的风险

- 本工作区没有 P1 Rust workspace 文件。主代理需集成其他所有者交付后才能运行；测试命名接口必须同步确认。
- 模块新增未在探针中的依赖需单独审阅固定版本；manifest 静态约束不是传递依赖审计的替代。
- 9.6 registry 当前可拉取性尚待远程门禁验证；拉取失败必须报告受阻，不能默默抬高最低支持版本。
- 首次 bootstrap lock 必须回收提交并 locked 重跑；工具链/依赖可获得性、YAML 展开、脚本测试、Rust 编译和两库行为全部尚待 Actions 验证。
