# P0 远程静态台账一致性检查

状态：已交付、未执行验证。P0 未验收，不进入 P1。仅新增本说明、`scripts/ci/check-inventory.py`、`.github/workflows/p0-inventory.yml`；不修改已通过的 p0-baseline.yml，不提交或推送，不执行本地脚本/构建/测试。

目标主库遵循最新用户决定：**SQLite + PostgreSQL**；MySQL 不支持、不迁移，不增加 MySQL 验收门槛。这里不连接任何数据库。

## 输入与实际比较

固定上游 `xiaocongyu66/new-api@17970da4571e81308f176a0e61a38276e5771606`，runner 核对 checkout HEAD。集成仓库必须同时具备 `docs/contracts-inventory.md`、`docs/routes-coverage.md`、`docs/data-jobs-inventory.md`；缺文件是 ERROR，不是覆盖通过。开发工作区尚未包含这些并行交付，由主代理合并，而不是复制开发机文件供远程隐式依赖。

Python 标准库读取 Go 文本，不导入、编译或执行上游 Go，不安装依赖，不执行 go generate/init，不启动服务、容器或访问真实业务服务。唯一子进程为只读 git rev-parse。

路由受控语法针对固定 SHA：

- 去除 Go 行/块注释，保留字符串与原行号，注释内注册不计数。
- 解析单个 contract.Engine/Routes 参数的顶层函数、字面量 Group 和显式 HTTP verb 调用；沿 helper 实参传递完整前缀。MJ helper 两个挂载分别展开，不按 handler 去重。
- 单独支持 channelPermissionRoutes 的字面量 method/path 表及对应循环 Handle；不把动态 Handle 偷换成无路由。其他无法解析的注册形式记录 UNDETERMINED。
- 默认使用 !dev 空 helper；另解析 dev helper 增量，保留条件标记，不重复复制生产路由。dev 根前缀按固定基线 `/api/user` 明确指定，不宣称解释任意 build constraints。
- 台账每个显式方法行必须有 P1–P9 阶段及已知源代号/注册行。以 `(method, 完整 path, 源文件, 注册行)` 多重集合双向比较，报告缺项、多项、重复；MJ 逗号证据同时检查其 helper 引用确实指向调用语句。
- 路径合并保留参数名、大小写、尾斜线；按 route_snapshot_test.go 的 join 规则，不做浏览器 URL 归一化。
- 按 API/dashboard/relay/video 分别与四份现存快照双向比较，再核对 routes-coverage.md 对应四行总数。预期生产 302/4/71/11，dev 增量 1；实际数量写报告，不用这些数字替代逐项差集。

此解析器是固定源码的受控语法检查，不是完整 Go 编译器或控制流解释器。未知语法、无法定位 helper、重复/未知 Group receiver 不得算通过。未来升级上游必须重新审阅语法、条件与注册入口；禁止只修改固定 SHA 绕过复核。静态文件/fallback、隐式方法处理、鉴权、中间件、可达性与注册先后行为不属于集合等价结论，归原阶段专项验证。

## 模型与任务：明确未判定

扫描 apps/api 下非测试 Go 文件（包含嵌套模块）。对字面量 `Migration{Model: &Type{}, Name: "..."}` 提取模型、来源行并要求 data-jobs 表中同名模型和阶段映射，缺映射报 FAIL。它仅是候选对账：尚未证明注册调用包含关系、同名类型包身份、直接 AutoMigrate、动态 SQL、实际表结构/所有权全集。

枚举 go、RegisterSystemTaskHandler、time.NewTicker/AfterFunc 候选调用位置供补录；不将命中或文件存在视为任务归属证明。动态 Type() 分派、异步封装、init/build tags、入口与逐项台账映射仍 **UNDETERMINED**。当前报告故意不能宣称模型或任务全集通过。

## 结果与门禁

- `report.json`：目标/上游 SHA、run/attempt、环境、输入摘要、完整路由及台账项、差集错误、模型映射候选、异步入口候选和未判定原因。
- `summary.md` / step summary：明确区分 `PASS_STATIC_EXPLICIT_ONLY` 路由子结论和整体 `PARTIAL`。测试执行数为 0，不把静态记录数当测试数。
- 退出码 1：差异、缺文件或解析异常；2：无已知差异但仍有未判定范围；3：拒绝本地执行。
- **当前整体最多 PARTIAL，退出码 2 会使 Actions job 非绿，这是刻意行为。** 不使用 continue-on-error，不吞退出码。主代理可引用路由子项结果，但不能凭子项 PASS 宣布整体 P0 验收；模型/任务范围闭环前不能简单把 2 改成 0。

工作流使用标准 ubuntu-24.04、contents:read、10 分钟超时、分支 concurrency，checkout/upload-artifact SHA 复用已经验证的基线配置。setup 前保存 environment.json；always 上传报告，保留 7 天。不上传源码树、数据库、环境全集或秘密；强制取消/runner 丢失可能没有完整 artifact，需如实记录。

## 集成交接与剩余阻塞

主代理合并三个新文件及最新三份台账后，获授权提交/推送集成 SHA，在远程运行本工作流；本代理不执行提交、推送或本地脚本。取回该精确 SHA/run/attempt 的 report.json，先检查 routes_status 和逐项差集，再交独立 verification。若失败按报告修正解析器或台账，不能改快照凑数。

尚无本次工作流运行 ID、Python 语法/执行验证或独立复核 PASS。必须由 Actions 首跑验证实现；模型完整注册/动态 SQL 与异步任务逐入口映射尚未闭环。SQLite/PostgreSQL 真实连接和运行时路由契约依所属阶段推进，不把未来实现验收冒充本次静态对账。
