# P2 setup 实现契约（冻结；非验收）

## 范围与依据
Rust 1.99.1、Edition 2024、Axum/SQLx、模块化；仅 SQLite/PostgreSQL，禁 Moka/MySQL。基准为 `/root/newapi-rs/docs/rust-backend-migration-plan.md` §P2、`contracts-inventory.md` §0.1及路由表、`schema-inventory.md` §2/§6；上述文件的字段、错误文本与索引清单通过引用构成本契约，不重复调研。本文件只约束初始化/status及注册入口；登录、会话撤销、权限隔离、API Key/令牌限制、2FA、限流/Redis仍是P2必交，不因首批拆分删除。

## schema门禁与事务（首批必须）
现有 `/root/newapi-rs-p2-setup/crates/storage/src/lib.rs` 只有连接/关闭，SQLite `create_if_missing(false)`，没有DDL/迁移器。Go有注册迁移、后置修复及SQL迁移，不能把模型清单当已可执行DDL。
启动与HTTP禁止自动建表/升级；只读检查既有完整兼容schema，缺表/缺列/DB错误返回503 `{success:false,message:"数据库结构未就绪"}`，不得当作未安装或写setup。只建 users/options/setups 不得宣布系统setup完成。首批使用隔离、完整Go基线schema；新库初始化须另交显式离线、双库、完整schema准备能力及验收证据，未交付标受阻，非取消安装目标。旧root无setup不照搬Go启动自动补写，交显式POST确认；旧记录修复也不得启动偷偷执行。

`setups`：id主键；version varchar(50) NOT NULL DEFAULT 'legacy-unknown'；initialized_at bigint NOT NULL DEFAULT 0。POST固定id=1、版本字符串、Unix秒；任意既存记录均算已完成。
`users`完整列/索引沿用schema §2，禁止精简建表；最小创建值：username/password、display_name、role/status、quota、group、auth_version、created_at、access_token。root=角色100/状态1、Root User、quota=100000000、group=default、auth_version=1、access_token=NULL；其余按Go零值/默认，deleted_at=NULL。无内置root密码，username/password来自向导；不能生成root/123456。保留username/aff_code/access_token唯一性、软删及aff_history列名；邮箱只有普通索引，不捏造唯一约束。密码bcrypt cost10，兼容Go散列，禁止双重hash；超过72字节不得静默截断。
事务重新检查setup及未软删role=100用户，插入setup与必要root原子提交；跨进程依数据库串行化，不能只用进程锁。SQLite写事务/PG锁并配合主键冲突处理；冲突后重新判定已完成。模式写入options键 SelfUseModeEnabled/DemoSiteEnabled、字符串true/false。Go模式写在事务外；本契约明确收紧为与root/setup同事务，提交后刷新内存，失败全回滚（须差分记录）。

## HTTP（首批必须）
* GET `/api/setup`：200 `{success:true,data:{status,root_init,database_type}}`，无message。已完成为true/false/空串；否则root实际存在值及sqlite/postgres。忽略t。
* POST同路由：匿名、有请求体限制；JSON username/password/confirmPassword及大小写精确的SelfUseModeEnabled/DemoSiteEnabled，缺省空串/false。无root时依次检查用户名UTF-8字节≤12、密码一致、字节≥8；不额外发明非空规则。有root跳过此三项，不覆盖账户。业务结果均200，无data/code；成功message=系统初始化成功。绑定、长度、模式保存、创建失败等原文逐项执行contracts §0.1表；不得回传DSN/原始SQL错误，用脱敏错误分类代替错误后缀。重复为系统已经初始化完成。
* GET `/api/status`：200 `{success:true,message:"",data:{…}}`。完整键名、类型、条件字段以 `/root/newapi/apps/api/internal/transport/handler/handle_misc.go:49–166` 为规范，禁止使用P1字符串data封装。setup取已提交持久状态。默认theme=default、system_name=New API、logo/footer_html/theme_customization为空、default_collapse_sidebar=false、data_export_default_time=hour。认证默认配置password_login/register/password_register=true、email_verification及OAuth/Turnstile=false；**有效声明=配置允许且实现可用**，因此未实现登录/注册及drawing/task/export/checkin等一律false，不照抄Go true。其他货币/面板/Passkey默认引用对应settings getter，不造零值；可选api_info/announcements/faq仅有效启用时出现；无可用自定义OAuth省略custom_oauth_providers。不得输出secret。

## 阶段内递增，但P2结束必须闭环
四入口均匿名：GET `/api/verification?email=`（邮箱限流+Turnstile）、GET `/api/reset_password?email=`（关键限流+Turnstile）、POST `/api/user/register`（关键限流+体限+Turnstile）、POST `/api/user/reset`（关键限流+体限）。handler业务包络200 success/message；未实现阶段明确失败且关闭能力，不返回假成功。中间件拒绝按现有contracts对应条目验收。
注册接收username/password/email/verification_code/aff_code，trim用户名、规范邮箱；用户名≤20字符、密码8–20字符；忽略客户端role/quota，创建普通角色1。邮箱验证启用才写邮箱；事务内邮箱互斥检查、hash、随机4位aff_code、QuotaForNewUser、setting及用户插入，软删用户名不可重用。默认token、邀请奖励、侧栏与审计是后续子批交付，不得吞失败；不在本文件扩展账务实现。
验证码实际为UUID去横线前6位（非纯数字）、TTL10分钟、purpose隔离。重置链接token32位；GET重置对不存在/歧义邮箱同样200成功空message。POST重置只收email/token，不收新密码；成功data为随机12位密码，旋转hash/auth_version并撤销会话、消费token，防并发重放。Go验证仅比较、重置成功后删除；原子消费是P2安全收紧，必须记录差异。SMTP、Clock、验证码存储可替换；多实例共享及Redis故障策略不得留到P2以后。

## 首批公开边界与测试路径
建议顺序：storage只读 `inspect_schema()->Result<SchemaReadiness>` → identity `root_exists(tx)`/`create_root(tx, RootDraft)`及 `PasswordHasher::{hash,verify}` → ops `SetupService::{inspect,complete}` → status `CapabilitySnapshot::effective(config,implemented)` → transport DTO/路由。事务由ops持有，identity不得另开连接提交；错误区分AlreadyInitialized/SchemaNotReady/Unavailable/Validation；Clock注入，密码类型不得Debug。
拟新增测试（本轮不创建）：`/root/newapi-rs-p2-setup/crates/ops/tests/setup_contract.rs`、`/root/newapi-rs-p2-setup/crates/identity/tests/registration_reset.rs`、`/root/newapi-rs-p2-setup/crates/storage/tests/schema_readiness.rs`；扩展 `/root/newapi-rs-p2-setup/apps/server/tests/http_contract.rs`。双库覆盖空/部分schema拒绝、完整schema、有root/旧setup、UTF-8边界、bcrypt、事务逐点失败、跨进程竞争仅一次提交、重启状态、status全部键/默认/能力关闭、邮箱重复/验证码过期/重放/禁用/限流及敏感日志。远程Actions留SHA/run/数量/跳过数及独立判定；本轮仅文档，未构建、测试、运行脚本、提交或推送，不宣称实现PASS。
