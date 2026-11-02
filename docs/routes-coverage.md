# P0 路由注册集合覆盖报告

## 结论与证据边界

用户最新确认：目标主库仅 **SQLite + PostgreSQL**，尽量兼容原 schema；**MySQL 不支持、不迁移，不进入目标实现或验收矩阵**。旧 Go/CI 中的 MySQL 信息仅为历史事实，不作为后续待补验收或 P0 阻塞。两库兼容仍按所属阶段验证，本次范围更新不构成验收通过。

2026-11-02；只读基线 `/root/newapi` HEAD 为 `17970da4571e81308f176a0e61a38276e5771606`，本次 `git status --short` 显示原仓库仅 `.claude/` 未跟踪。交付位置为 `/root/newapi-rs-p0-contracts/docs/`。主计划仍为 `/root/newapi-rs/docs/rust-backend-migration-plan.md`，P0 未验收，P1–P10 未开始。

**已静态闭环：固定生产源码注册集合 ↔ 四份现存快照 ↔ contracts-inventory.md 第 2–3 节的 method/path 与阶段归属。** 本次阅读全文、人工逐项对照，未发现生产路由缺项、多项或重复键；本次人工对照不是程序差集或独立测试 PASS；已有远程 CI 基础交付 success/PASS 及范围见第 6 节。本任务未运行本地脚本、构建、测试、服务、容器，未另行触发远程运行，未提交推送。既有 handler 字段补录保留，不扩大未来阶段字段专项。

## 1. 计数口径与逐项对照入口

以下源路径均相对 `/root/newapi/apps/api/internal/transport/compose/`。计数单位是保留大小写、参数名和尾斜线的 `(method, 完整注册 path)`，不是 handler 数、唯一 URL 数、物理 Fiber 栈层数或可访问文件数。

| 集合 | 固定源码注册点 | 台账逐项入口 | GET | POST | PUT | PATCH | DELETE | 总数 | 阶段归属 |
|---|---|---|---:|---:|---:|---:|---:|---:|---|
| API | register_api.go:19–465，含 :358–359 两个 helper | 第 2 节及 2.1，排除 DEV 行 | 137 | 118 | 17 | 1 | 29 | 302 | 每行 P1–P7，交叉依赖保留 |
| dashboard | register_dashboard.go:11–22 | 第 3 节 D 四行 | 4 | 0 | 0 | 0 | 0 | 4 | P4 |
| relay | register_relay.go:14–230，MJ helper 调用两次 | 第 3 节 R 全部行 | 19 | 50 | 0 | 0 | 2 | 71 | P5/P6；依赖 P4/P7 |
| video | register_video.go:12–54 | 第 3 节 V 十一行 | 5 | 6 | 0 | 0 | 0 | 11 | P6 |
| **生产合计** | compose.go:15–18 | 第 2–3 节排除 DEV/Web 规则 | **165** | **174** | **17** | **1** | **31** | **388** | 每项已有归属 |
| dev 增量 | register_dev_autologin.go:1,14–20 | 第 2 节 DEV 行 | 0 | 1 | 0 | 0 | 0 | 1 | P2，仅 dev |
| **全部显式台账** | 生产 + 条件 dev | 不含 Web 行为规则 | **165** | **175** | **17** | **1** | **31** | **389** | 全部未开始 |

交叉核算：

- API = A 255 + C 46 + Z 1 = 302。C 为 `/:id/key` 单条加 `channelPermissionRoutes` 45 项（register_channels.go:51–95）；不能只数 `.GET/.POST` 而漏掉循环 Handle。管理主表 257 行含 A 255、Z 1、DEV 1，渠道表 46 行。
- relay = models 4 + playground 1 + realtime 1 + HTTP 已实现入口 17 + NotImplemented 12 + MJ 16×2 + Suno 3 + Gemini wildcard 1 = 71。NotImplemented 是必须保留的失败契约，不是待删注册。
- video = content 1 + `/v1` task 5 + Kling 4 + Jimeng 1 = 11。
- 四份 `testdata/routes_{api,dashboard,relay,video}.txt` 非空行分别为 302/4/71/11。人工逐项对照，无发现默认生产差集；远程机器比较仍待执行。
- 台账另有 4 行 Web 行为规则，389 + 4 = 393 个展示条目，但 **393 不是端点数**。默认无 dev 的同口径是 388 + 4 = 392 个“端点与规则”条目，同样不能与 388 endpoint 快照直接比较。

## 2. 388 快照为何不等于所有运行时行为

`route_snapshot_test.go:17–34,79–138` 使用记录型 engine，分别调用四个业务注册函数，随后排序比较 method/path。它不调用 SetRouter/SetWebRouter；Use、CORS、Compression、ServeAssets 为 no-op，NoRoute 仅保存链。因而：

1. 默认 `!dev` 没有 dev 登录；`dev` 构建多 `POST /api/user/dev/auto-login`，生产快照不能直接当 dev 快照。需独立断言默认 388、dev 389 及 dev 路由不存在/存在，不能为了 dev 测试而改生产总数。
2. 静态文件、SPA、重定向、压缩中间件不进快照。它们是层和规则，不是额外显式业务路由。
3. 快照排序掩盖注册先后；实际顺序是 API→dashboard→relay→video→Web/fallback。API 中 channels/authz 在 token 前；relay 中 MJ 两组在 Suno/Gemini 前。台账为阅读分组调整过显示顺序，必须按源码装配，不能照 Markdown 行序注册。
4. `GET /v1/models` 的 header/query 协议分支、Jimeng Action query、OAuth `:provider`、MJ `:mode`、Suno `:action` 不因参数取值增生注册行。QQ webhook 的配置 token 和 Pancake `:env` 是 handler 校验条件，不是条件注册开关。

## 3. 条件路由与 Web 四规则（全部有阶段）

| 项 | 源码事实/适用条件 | 计数 | 阶段与验证状态 |
|---|---|---|---|
| dev 登录 | `//go:build dev` 才注册；`register_dev_autologin_stub.go` 的 `!dev` helper 空函数 | dev +1；默认 +0 | P2；静态确认，生产缺席响应待远程 |
| 静态 probe | FRONTEND_BASE_URL 空，或 master 忽略该配置；SetWebRouter→ServeAssets(`/`, embedded web/dist) | 非显式 endpoint | P1/P9；文件清单和 HTTP 语义待远程 |
| 本地 API miss | 同上，asset 未命中且 RequestURI 前缀为 `/v1`、`/api`、`/assets`，RelayNotFound | 一条规则 | P1/P8；包括错误 method，响应待远程 |
| 本地 SPA miss | 同上，其余未匹配 URI 返回 index，200、no-cache | 一条规则 | P1/P9；最终 HEAD/body/headers 待远程 |
| 外置前端 miss | 非 master 且 FRONTEND_BASE_URL 非空；去末尾一个 `/`，301 到 base + RequestURI，不调用 SetWebRouter | 一条规则，和本地三规则互斥 | P1/P9；含 query、API miss 和 OPTIONS 待远程 |

依据 `compose.go:19–31`、`register_web.go:13–17`、`static/serve_assets.go:22–35`。本地分支并非按路径段排除，而是字符串前缀；`/mj`、`/suno`、`/pg` 等 miss 可走 SPA。此旧行为与“未实现 API 不得假成功”要求的差异需显式批准策略，不能默默扩大前缀拦截。外置分支也不能承诺 dev 缺席必然 404：未注册与最终 fallback 响应是不同命题。

## 4. HEAD、OPTIONS 与物理路由栈

依据 `/root/newapi/apps/api/internal/transport/fiberadapter/router.go`：

- :295–343 所有 verb 走 `app.Add`，GET **不走**会附带 HEAD 的 `app.Get`。生产显式 HEAD=0，OPTIONS=0；**自动 HEAD 增量=0**，不能把 165 个 GET 再复制成 HEAD 加入总数。
- :379–408 UseCORS 只追加 contract middleware，**不注册 OPTIONS endpoint**。其跨源 OPTIONS 分支能返回 204，但必须先进入含该链的 handler；不能把注释中的 preflight 行为当所有路径已经实测。
- :614–635 NoRoute 用一次 `app.Use` 装 terminal fallback，所有方法可以进入；:726–738 读取当前 engine pending 链后做 asset probe/no-route。SetRelayRouter 已在 root 增加 CORS，因此正常全量 SetRouter 的未匹配请求（包括 HEAD/OPTIONS）可能先被 root CORS 处理。跨源、同源、无 Origin 必须分测；不能承诺 OPTIONS 总是 204 或总是 404。
- :746–755 静态发送交给 filesystem.SendFile，HEAD 专门处理由依赖负责；本次未冻结其输出字节、Content-Length、Range 等语义。
- :603–608 设计上错误方法走 fallback，不默认 405；Axum 自动 HEAD/405 不能直接当兼容实现。
- 没有生产 Any 注册。Any 的九方法展开实现不是九条现存业务路由；app.Use/压缩等原生层的内部栈记录也不能加到 388。

这些是已读源码事实与装配推导，不是运行时通过结论。HEAD/OPTIONS 规则继承所属业务阶段；fallback/CORS 基础差分由 P1/P2 承担，完整兼容复验 P8。

## 5. 别名与同 handler 路径不去重

| 路径族 | 已纳入计数与差异边界 | 阶段 |
|---|---|---|
| `/dashboard/billing/{subscription,usage}` 与 `/v1/dashboard/billing/{subscription,usage}` | 两对明确同 handler 别名，共 4 行，不压成 2 行 | P4 |
| `/mj/...` 与 `/:mode/mj/...` | 同 helper 的 16 对路径，共 32 行；mode 值不再枚举；image 在 TokenAuth 前 | P6 |
| `/v1/models`、`/v1beta/openai/models`、`/v1beta/models`、`/v1/models/:model` | 共 4 行，但协议/header/query 分派不同，不能当等价别名删除 | P5/P6 |
| `/v1/models/*path` 与 `/v1beta/models/*path` POST | Gemini 两个入口各计 1；命名 wildcard 在 adapter 翻译成 `/*`，不是新增路由 | P6 |
| `/v1/video/generations` 与 `/v1/videos` 及各自 task GET | 兼容入口各保留，共 4 行；同 task handler 不代表 payload 完全相同 | P6 |
| `/api/user/groups` 与 `/api/user/self/groups` | 同 handler 的两个入口，N/U 权限不同 | P3 |
| 用户与订阅 epay/vmq/codepay notify 的 GET/POST | 每个完整路径两个方法分别计数，共 12 行；POST body limit 与 GET 不同 | P7（依赖 P4） |
| `/api/qqbot/webhook` 与 `/api/qqbot/webhook/*token` | 两条 POST，token 配置在 handler 校验，不合并 | P7 |
| `/api/channel/` 等有/无尾斜线客户端形式 | 仅原注册模板计数；不能凭浏览器调用再加隐式别名 | 各条所属阶段；P1/P8 方法/路径差分 |

其余共享 handler（Kling、音频、图像等）按台账逐项保留，不推断协议等价。注释掉的 `/api/midjourney`、`/api/user/tokenlog`、MJ `/notify` 不属于注册集合；前端 `/api/ratio` 文案不构成注册。未来新增业务必须另入台账，不能反向扩写旧 388 快照。

## 6. 已有远程基线、P0 收口与后续验证

证据来源为 `/root/newapi-rs/docs/ci-baseline.md`，本任务读取引用，未重新触发或独立复跑：

- 新仓库 SHA `6e599ec59837d645b4740ebe363790beda6b40f1`；run [41425478831](https://github.com/xiaocongyu66/newapi-rs/actions/runs/41425478831)，attempts 1/2 均 completed/success。首轮 CI 基础交付已有独立 verification PASS。
- 首轮 public-config 19 pass/0 skip、focused 295 pass/2 skip、full-api 2745 pass/7 skip、relaykit 280 pass/0 skip，四组命令退出码均为 0。包含子测试和跨套件重复，不是独立契约数；attempt 2 success 不表示重新统计上述数量。
- focused 包含 compose，full-api 包含 fiberadapter 等现有测试；不得再笼统声称这些包未远程运行。原生 MySQL/PostgreSQL 与支付签名 skip 仍保留为历史基线事实；其中 MySQL 不迁移，不要求补齐目标验收，PostgreSQL 仍属于目标主库。工具查询仅证明 Rust 工具存在。
- success/PASS 的范围是该 SHA 的 Go 基线与 CI 基础交付，不是完整契约矩阵、Markdown 三方差集、本次文档修订或整个 P0 的验收。

**P0 只冻结集合、契约、映射和基线。下列后续验收不前置为 P0 阻塞。**

| 检查 | 当前证据 | 阶段/后续责任 |
|---|---|---|
| 固定源码、快照、台账与阶段归属 | 人工逐项静态闭环；现有 Go 快照测试所在基线 success；未提供包含 Markdown 的三方机器差集 | P0 集合/契约/映射收口及本次文档独立复核；机器差集作为可复现增强，不将未执行冒充通过 |
| 默认/dev 条件集合 | 默认快照所在基线 success，dev 条件已静态冻结；ci-baseline 明确未含 dev tag | P0 记录条件和映射；P2 实现验收增加 dev/non-dev 独立断言，不能修改生产 388 来适配 dev |
| Fiber 可达性与顺序 | compose/fiberadapter 所在 focused/full-api 基线 success；不推出所有运行时组合均覆盖 | P0 引用现有基线；各迁移阶段增量差分，P8 全量回归 |
| HEAD/OPTIONS/错误方法 | adapter 装配契约已静态记录；完整 Origin×方法×路径×前端分支矩阵未证明覆盖 | P1/P2 基础行为验收，P8 完整兼容复验，不新增为 P0 实现验收门槛 |
| 静态资源与环境配置 | P0 挂载/fallback 条件及阶段映射已记录；CI 使用 embed 占位，不是生产前端产物 | P1 基础行为、P8 E2E、P9 固定真实 frontend artifact/嵌入清单与构建验收 |
| 公共配置故障与SQLite/PostgreSQL 两库 | 既有公共 handler fixture 与 Go 基线已有结果，不能替代加载失败/数据库不可用/SQLite/PostgreSQL 两库实连 | P1 专项验收，由主代理维护公共配置文档，本次不修改 |
| 真实供应商凭证/付费调用 | 未获授权或提供凭据，不宣称已验证 | P6 真实上游验收（contracts C06），不是 P0 阻塞；外部支付/通知依所属阶段 |
| P0 总门禁 | CI 基础交付 PASS，本文仅注册子项；本次修订尚待独立复核 | 主代理按 P0 集合/契约/映射及基线收口并取得独立结论，未验收不进入 P1；不得要求先完成 P1/P6 验收 |

未来阶段 handler 字段、故障/SQLite/PostgreSQL 两库、真实上游和完整流协议继续按所属阶段推进。不因现有基线 success 或注册静态闭环宣称完整契约/P0 已通过，也不再以“无 run ID、无 PASS”否定已有证据。
