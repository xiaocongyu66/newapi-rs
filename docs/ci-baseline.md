# P0 远程 CI 基线

状态：配置已编写，未执行；P0 不得据此标记已验收。所有构建、测试、脚本执行仅允许在 GitHub-hosted Actions；本次没有本地构建、测试、启动服务或容器验证，也没有提交、推送或触发远程运行。

## 源码与执行边界

- 上游：`xiaocongyu66/new-api`，固定 commit `17970da4571e81308f176a0e61a38276e5771606`。
- 独立 checkout `upstream-reference/` 使用固定 SHA、禁用凭证持久化，仅供读取；测试在 `$RUNNER_TEMP/p0-source/` 副本中执行。不会修改或推送上游。
- 新仓库 CI checkout 位于 `migration/`。测试不依赖开发机路径。
- 仅标准 `ubuntu-24.04` runner，`contents: read`，按分支/PR 取消过期运行；Go 两个矩阵任务各 35 分钟，Rust 工具链任务 5 分钟。不创建服务、容器、部署或付费资源。
- 集成者首次推送前必须确认目标仓库公开、账号可免费使用标准 Linux runner；额度或账户策略不允许时保持受阻，不自动购买额度。
- push、pull_request 和 workflow_dispatch 均可触发，无路径过滤；不使用 pull_request_target、secrets、生产 DSN 或供应商密钥。

## 源码事实与命令

两个模块 `apps/api/go.mod` 和 `apps/api/modules/relaykit/go.mod` 均声明 **Go 1.27.3**。按实际文件交由 setup-go 安装，`GOTOOLCHAIN=local` 禁止静默切换，`GOFLAGS=-mod=readonly` 禁止改写模块声明。工具链或依赖无法获取时必须失败，不得降级版本、改 go.mod 或忽略错误。版本可用性尚未经远程运行确认。

上游 `.github/workflows/ci.yml` 使用 `with_gvisor,with_wireguard,with_utls`，设置 `GOWORK=off`，并为 `apps/api/main.go` 的 embed 创建 `web/dist/index.html` 占位。本工作流沿用这些测试构建条件，但只在临时副本放置空占位；它不是前端产物，不能作为前端或生产打包验收。

API 任务按顺序执行以下三组；即使前组测试失败也收集后组结果，最终任一失败均返回非零，不是假绿：

1. `go test -json -count=1 -timeout=8m -p=2 -tags with_gvisor,with_wireguard,with_utls -run '^TestP0PublicConfig$' ./internal/transport/handler`
2. `go test -json -count=1 -timeout=8m -p=2 -tags with_gvisor,with_wireguard,with_utls ./internal/transport/handler ./internal/transport/compose ./internal/dbinfra`
3. `go test -json -count=1 -timeout=8m -p=2 -tags with_gvisor,with_wireguard,with_utls ./...`

relaykit 独立模块另行执行 `go test -json -count=1 -timeout=8m -p=2 ./...`；父模块 `./...` 不会遍历嵌套模块，不能替代这一步。`-count=1` 禁止测试结果缓存，setup-go 根据两个 go.sum 缓存模块依赖和 Go 构建缓存。并行包数限制为 2，减少标准 runner 峰值内存。

全量测试静态评估可尝试：上游已有相同 tags 的全量 CI；本工作流保留全部 `./...`，不排除失败包。尚未证明其在当前标准 runner 时限、内存和依赖网络环境下通过。超时或资源不足必须保留失败证据后定向调整，不得将只跑 focused 描述为全量通过。

## 公共配置补充 fixture

上游 handler 已有 status/OIDC 等测试，但源码搜索未发现 notice/about/home-page/legal handler 的专门测试。`scripts/ci/public_config_test.go.txt` 作为必要 CI fixture，仅复制到临时副本的 handler 包，不修改上游 checkout。

新增 `TestP0PublicConfig` 直接调用真实 handler，检查 Notice、About、HomePageContent、UserAgreement、PrivacyPolicy 的 HTTP 200、完整 JSON envelope，以及缺失/空/带 Unicode 和 HTML 文本配置；法律配置使用真实 settings 映射。测试不 parallel，并恢复共享状态。法律配置的 missing 场景只代表 settings 零值，不声称测试了法律配置持久化缺失处理。路由注册另由完整 compose 测试覆盖；fixture 的请求路径不是独立路由可达性证明。

现有 dbinfra 全包涵盖 options、迁移、setup、日志等；此基线不新增业务实现或 Rust 服务。

## 证据与失败规则

每个 Go 矩阵任务在 checkout/setup 前创建 `environment.json`，包含新仓库 SHA、上游 SHA、run ID、attempt、runner 镜像与平台。执行后另保存：

- `go-version.txt`：实际工具链版本。
- 每组 `*.jsonl` 原始 Go 事件与 `*.stderr.log` 编译/依赖错误。
- `results.json`：逐组精确命令、目录、退出码、test/package pass/fail/skip 数量及跳过名称；test 数量包含子测试，不等于顶层函数数。
- Actions step summary：汇总数量，不替代完整日志。

零完成测试不能算通过。允许保留上游原生 skip 以准确复现其单元测试基线，但 skip 不构成三库或真实供应商验收。没有 `continue-on-error`、`|| true` 或静默删除失败用例。setup 失败时不会产生 results.json，environment 中明确 tests 未运行，应结合 Actions step 结果判定受阻。

artifact 使用 always 上传，保留 7 天；强制取消、runner 丢失或 job 超时可能导致上传不完整，此时必须记录证据缺失，不能声称通过。仅上传受控 CI 日志，不上传源树、环境变量全集、数据库文件或生产数据。公开仓库 artifact 可能被仓库可读用户下载，因此只允许脱敏 fixture；不使用外部报告服务。长期验收记录由集成者归档至仓库文档。

Rust 任务仅记录 runner 自带 `rustc --version --verbose` 与 `cargo --version` 的输出、退出码、commit/run/attempt。它证明工具存在，不证明依赖兼容、构建或 Rust 实现已验收；P0 尚未引入 Cargo workspace，故当前无 Cargo 缓存或 fmt/check/clippy/test。进入实现阶段后应添加锁定工具链、Cargo.lock、Cargo 缓存及完整检查，不得用本任务替代。

## Actions SHA 来源

2026-11-02 使用只读 `gh api repos/actions/<name>/commits/<tag> --jq .sha` 查询，未自行猜测 SHA：

| Action | 查询 tag | 固定 SHA |
| --- | --- | --- |
| checkout | v4 | `11d5960a326750d5838078e36cf38b85af677262` |
| setup-go | v5 | `40f1582b2485089dde7abd97c1529aa768e1baff` |
| upload-artifact | v4 | `ea165f8d65b6e75b540449e92b4886f43607fa02` |

## 未覆盖与受阻项

- 尚无远程 run ID、退出码或测试数量，脚本及 fixture 尚未经执行验证；只有静态审阅，不能宣称 PASS。
- 三库真实服务没有启动。上游 identity/handler 的 `TEST_MYSQL_DSN`、`TEST_POSTGRES_DSN` 测试会原生 skip；SQLite/模拟依赖通过也不能代替 MySQL/PostgreSQL 验收。阶段三库矩阵仍须独立实现。
- 上游 Waffo Pancake 有明确的 SDK 签名测试 skip；真实支付/通知/供应商调用未获授权，不补生产凭证。
- race 专项、dev build tag、前端构建/E2E、性能/压力与部署未列入本 P0 基线，不能以本工作流替代后续阶段。
- 补充公共配置 fixture 不覆盖数据库不可用、配置加载失败、错误方法及完整前端差分，这些仍归 P1 契约验收。
- 本工作流成功只证明此 Go 基线和工具存在；P0 的台账、独立 verification 等其他门槛仍需分别通过。

## 集成后仅远程验证

1. 集成者审查并提交上述文件到独立 newapi-rs 开发分支，确认免费 runner 条件后按授权推送。不要向上游推送。
2. 用 `gh run list -R <owner>/newapi-rs --workflow p0-baseline.yml --commit <集成SHA>` 找到运行；用 `gh run watch -R <owner>/newapi-rs <run-id> --exit-status` 等待。
3. 用 `gh run view -R <owner>/newapi-rs <run-id> --log` / `--log-failed` 检查精确版本、公共配置、focused、全量 API、relaykit 与工具链任务；下载 artifacts 留存。失败先根据日志定位，禁止无意义循环复跑。
4. 独立验证者绑定精确集成 SHA 和 attempt，核对每组退出码、非零测试数量、skip 明细与原始 JSON；抽查至少公共配置、compose/dbinfra focused、relaykit 三组命令。任何未执行或证据不足返回 PARTIAL/受阻，而非验收。
5. 验证后由主代理更新主计划的阶段记录。本工作区不修改主计划，不自行宣布 P0 完成。
