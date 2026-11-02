# P0 公共配置读取契约（源码级，不是运行验收）

基线 `17970da4571e81308f176a0e61a38276e5771606`；日期 2026-11-02。状态：进行中，P0 未验收，P1 未开始。本文只读 `/root/newapi`，不修改主计划或架构。未执行构建、测试、服务、容器、自写脚本；无运行 fixture、无提交推送。

证据标记：**事实**=已读取源码明确表达；**推断**=由调用路径导出、尚未运行；**待验证**=Actions 才能冻结。以下源缩写 `B/` 表示 `/root/newapi/apps/api/`，`W/` 表示 `/root/newapi/apps/web/src/`；每条行号均属于上述固定基线。

## 已确认的实现决策

2026-11-02 用户确认公共 GET 保持原缓存行为：运行时数据库故障保留最后有效配置和原 JSON envelope；加载错误与缺配置在加载层、日志、就绪状态区分。首次加载失败不能伪装就绪。此决定已写入主计划 P1；本文后续对原 Go 行为的描述仍是兼容证据，不将历史差异重新列为未决问题。

## 1. 五条公开 GET

**事实（每行）**：均无 handler 请求体、路径参数或查询字段；不检查登录身份。继承全局链和 API 的 RouteTag、压缩、BodyStorageCleanup、GlobalAPIRateLimit，不额外附加匿名请求体限制、DisableCache 或鉴权。注册证据 `B/internal/transport/compose/register_api.go:19–39`；全局链仍以总台账为准。

| 方法/路径 | handler 证据（B/internal/transport/handler/handle_misc.go） | DB key（大小写敏感）/内存来源 | 默认值与证据 |
|---|---|---|---|
| GET /api/notice | GetNotice:177–186 | `Notice` / common.OptionMap | string `""`；B/internal/settings/settings.go:209 |
| GET /api/about | GetAbout:188–197 | `About` / common.OptionMap | string `""`；同文件:210 |
| GET /api/home_page_content | GetHomePageContent:228–237 | `HomePageContent` / common.OptionMap | string `""`；同文件:211 |
| GET /api/user-agreement | GetUserAgreement:199–206 | `legal.user_agreement` / security.GetLegalSettings().UserAgreement | string `""`；B/internal/security/configure_legal.go:5–20 |
| GET /api/privacy-policy | GetPrivacyPolicy:208–215 | `legal.privacy_policy` / security.GetLegalSettings().PrivacyPolicy | string `""`；同文件:5–20 |

**事实（五条共用响应）**：HTTP 200，JSON 对象 `{ "success": true, "message": "", "data": <string> }`。没有省略字段、分页、业务错误分支或 404 空值分支。服务端不 trim，不把 URL 当跳转，不解释 HTML/Markdown；它们都是字符串。前三条持 OptionMap 读锁直到 JSON 调用结束；法律两条直接读全局结构体指针，不持这个读锁。五个 handler 均忽略 c.JSON 返回错误，无自行设置 Cookie 或缓存头。

**推断**：缺少传统 map key 的 Go string 零值仍为 `""`；法律缺行保持注册默认值。空白与空串应在原始 JSON 中区分，不能按前端 trim 结果更改服务端行为。

**待验证**：完整 Content-Type/charset、压缩、HEAD/OPTIONS、错误方法（不能预设 405）、尾斜线、限流/GeoBlock/recovery 错误、请求头和跨域、传输写失败；handler 200 不代表任何请求必达 handler。

## 2. DB → settings → handler 的真实时序

1. **事实**：`B/internal/dbinfra/store_options.go:42–51` 的 Option 有 `Key string`（json key，主键）、`Value string`（json value）；AllOption 用 DB.Find。法律 key 由模块名 `legal` + `.` + JSON tag 得到，见 `B/internal/security/configure_legal.go:5–20`、`B/internal/settings/config.go:68–85,113–123`。默认 GORM 表命名推导为 `options`，实际 naming strategy/schema 仍待远程核对。
2. **事实**：`store_options.go:54–69` 先 SeedOptionMap 再全表加载；Seed 的传统默认值见上表，注册配置导出进 map 见 `settings.go:279–285`。加载时逐行 ApplyOption；**AllOption 的错误被丢弃**，ApplyOption 错误仅 SysLog。启动接线 `B/main.go:412`。
3. **事实**：`settings.go:335–342` 在写锁内更新 map，再派发分层 key；`:656–681` 用点号拆模块/字段，从 GlobalConfig.Get 拿指针并更新。`config.go:184–203` 以 JSON tag 匹配并 SetString。法律接口读取的是结构体字段，不是传统 `UserAgreement`/`PrivacyPolicy` key。
4. **事实**：`store_options.go:84–105,27–39` 校验后事务 FirstOrCreate/Save，事务成功才 ApplyOption（网关路由项另有分支；本切片不应混入网关配置）。因此正常更新进程内无需重启；DB 写失败不走该 ApplyOption。
5. **事实**：`B/main.go:129` 启动 SyncOptions；`store_options.go:72–77` 先 sleep 再加载，只覆盖读取到的行，不清空缓存。`B/internal/common/init.go:109` 读取 SYNC_FREQUENCY，默认 60 秒（运行最终值及 Redis 初始化影响待验证）。
6. **推断**：进程已加载后 DB 不可用，GET 仍可返回缓存的 200；加载失败不能从 GET 区分“DB 不可用”和“确实未配置”。外部删行不会使当前进程值自动恢复默认，多实例经轮询最终可见但并非强一致。法律结构体读写未共享锁的并发安全需要 Actions race 验证，不可声称线程安全。

**与主计划 P1 的边界**：主计划要求区分缺配置与 DB 错误；Go 这五条 GET 没有这种错误表达。用户已确认 GET 保留缓存及原 envelope；缺配置与加载失败在加载层、日志、就绪状态区分，此项不再待审批。不能虚构 Go 500 fixture。首次 DB 初始化失败是否阻止进程启动，另须追踪 main/db 初始化；本节只断言 option loader 的行为。

## 3. 管理更新入口

**事实**：`B/internal/transport/compose/register_api.go:298–302` 的 `PUT /api/option/` 更新组使用 AdminAuth + SystemSettings 权限。`B/internal/ops/manage_options.go:83–102` BindJSON 后把 value 转字符串：bool/float64/int 走 Interface2String，其余 fmt `%v`；因此不能把这个入口描述为仅接受 JSON string。解析失败 HTTP 400 `{success:false,message:"无效的参数"}`。`:368–380` 持久化失败经 `common.CtxApiError` 返回 HTTP 200 `{success:false,message:err.Error()}`，成功 HTTP 200 `{success:true,message:""}`，无 data。`B/internal/common/transport.go:53–58` 定义该失败包装。

**事实**：公共读取没有内容校验分支；通用配置校验器 `B/internal/settings/settings.go:116–162` 未为本五个 key 添加专门 HTML/URL/string 内容校验。更新 handler 其他专用 key 分支不代表本切片也有那些错误。

**待验证**：通用更新请求 key/value 缺失或 null 的具体串化结果、鉴权错误、管理界面保存与 query invalidate、DB 保存后内存应用异常、原始数据长度与数据库方言限制。不要把本节当作完整管理配置端点验收。

## 4. 前端消费（事实）

| 端点 | 请求与渲染/缓存证据 |
|---|---|
| notice | W/lib/api.ts:92–99 返回完整 res.data，类型 success:boolean，message?/data?:string；W/hooks/use-notifications.ts:71–101 queryKey notice、staleTime 5 分钟，仅 success 时取 `(data || '').trim()`；W/components/notification-popover.tsx:200–208 空态或 RichContent（该位置为检索定位，完整组件渲染待读）。 |
| about | W/features/about/api.ts:23–25 返回 res.data；index.tsx:115–185 从 data.data trim，不额外判断 success；空内容显示 EmptyAboutState；HTTP URL 用 sandbox iframe；HTML 用 isolated RichContent；其余 Markdown。 |
| home_page_content | W/features/home/api.ts:31–33 返回 res.data；hooks/use-home-page-content.ts:28–83 先读取 localStorage 同名 key；成功且 data 非空覆盖并保存，否则清空并删除 key；网络异常 toast，保留此前缓存，finally 标记 isLoaded；原字符串交给 isHttpUrl，不在此 hook trim。最终首页组件渲染待读。 |
| user-agreement | W/features/legal/api.ts:23–25；共享 legal-document.tsx:39–143，query staleTime 10 分钟、trim；!success 或空内容显示 message/emptyMessage，URL 是新标签链接而非 iframe；HTML isolated，其他 Markdown。具体页面接线 W/features/legal/user-agreement.tsx:29 为检索定位待完整复核。 |
| privacy-policy | W/features/legal/api.ts:28–30；同一 LegalDocument 上述分支；具体接线 W/features/legal/privacy-policy.tsx:29 为检索定位待完整复核。 |

**推断**：更新在后端生效不等于当前打开页面立即更新，React Query staleTime 和 home localStorage 会影响观测。法律文档是否存在还影响注册同意 UI；`W/features/auth/components/legal-consent.tsx` 与 `/api/status` 的法律能力字段尚未闭环，不能标完成。

## 5. 仅 GitHub Actions 的后续验证矩阵

以下全部 **待验证**，不是已执行或已通过。授权集成者将文档合并后，在固定 Go 基线的 Actions runner 建隔离测试库与测试进程；不得连接生产服务。

- 五端点 × 缺行/空串/空白/Unicode/Markdown/HTML/HTTP URL，比较状态与 JSON 字段类型及原始字符串；不要比较 JSON key 顺序。
- 每种目标数据库 SQLite/PostgreSQL（MySQL 已获批不迁移）：初次载入、管理更新后本进程、第二进程轮询、重启、外部删除行、初始查询错误与加载后 DB 断开；对比实际 Go 行为并单独列 P1 计划差异。
- 使用真实路由链测匿名访问、错误方法、HEAD/OPTIONS、尾斜线、限流、压缩/Content-Type；无效配置和 DB 不可用不能由成功空 fixture 代替。
- Actions race 检查法律结构体并发读写；前端检查空值清缓存、错误保留缓存、URL 展示方式和法律同意依赖。
- 保存来源 SHA、workflow run ID、命令、退出码、测试数/跳过数、脱敏响应 artifact；独立复核者据该 SHA 给 PARTIAL/PASS/FAIL。上述完整矩阵属于 P1 公共配置实现验收，不是开始 P1 的前置条件。P0 负责冻结本契约、覆盖映射和测试方案；已有 Go handler 基线证据见 ci-baseline.md，未覆盖项须在 P1 如实验证，不能据现有基线宣称全矩阵通过。

本轮不新增机器可读 fixture，避免把静态推导冒充运行采集。剩余缺口包括中间件错误、完整 options 更新 UI、启动 DB 错误路径、法律锁语义、frontend status/consent、三库基线与远程证据。
