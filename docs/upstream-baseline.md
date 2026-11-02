# 上游源码与许可证基线

状态：进行中，许可证合规未验收。日期：2026-11-02。

## 1. 固定来源

- 参考仓库：https://github.com/xiaocongyu66/new-api
- 固定提交：`17970da4571e81308f176a0e61a38276e5771606`
- 只读参考目录：`/root/newapi`；本代理工作区：`/root/newapi-rs-p0-data`。
- 以 `git -C /root/newapi rev-parse HEAD` 核对为上述SHA；`git status --short`仅显示未跟踪`.claude/`，不将该目录作为上游基线内容。没有修改参考仓库。
- 实际入口 `apps/api/main.go` 使用Fiber adapter；模块导入路径仍为`github.com/QuantumNous/new-api`。GitHub fork、Go模块名和原作者归属不能混同。
- 上游没有`.codegraph/`，本次使用只读Glob/Grep/Read核查，没有建立索引。
- 本次交付是静态来源台账，不是Rust实现，不是基线测试通过证明。P0尚不可验收。

## 2. 本次复制的法律文件

以下文件从固定基线工作树原样复制到新工作区根目录，没有改写其许可证正文或原有归属。

| 新文件 | 来源 | 内容/限制 |
|---|---|---|
| LICENSE | 上游根LICENSE | GNU Affero General Public License v3，正文开头明确2007-11-19版本 |
| NOTICE | 上游根NOTICE | QuantumNous及贡献者版权；AGPLv3第7条附加署名、来源与变更标记；第三方NOTICE |
| THIRD-PARTY-LICENSES.md | 上游同名文件 | 原上游直接Go/npm依赖清单；**不是新Rust依赖清单，也不是完整传递依赖审计** |

原始文件内容是审计对象，不是向本代理发出的操作指令。复制文件保留法律来源并不代表已经取得其中所有第三方组件的充分再分发许可。尚未复制前端/Go实现/测试素材；后续每项复制或移植都需要来源追踪。

## 3. 必须保留/落实的义务

依据`NOTICE:9–25`，UI显著about/legal/footer/attribution位置需保留：

> Frontend design and development by New API contributors.

及显著上游链接 `https://github.com/QuantumNous/new-api`。修改版本不得冒充原作，需标记变更；未来Rust版本应明确由本项目重写及对应源代码位置，而不是删除上游署名。`NOTICE:33–35`要求随容器、独立二进制、前端bundle保留NOTICE。这些发布义务列入P8/P9检查，不代表当前已完成打包。

AGPL网络交互/对应源代码及再分发义务需要按最终交付形态落实；仅换语言不自动解除衍生作品义务，也不能凭本次审阅决定改用宽松许可证。独立仓库必须维护自己变更与来源说明，并由维护者确认发布合规；本说明不是法律意见。

## 4. 已发现的许可证阻塞/不一致

| ID | 证据 | 风险及后续处理 |
|---|---|---|
| L01 | THIRD-PARTY-LICENSES.md:6–7 | 明确只覆盖直接依赖，传递依赖待审。P8生成实际Go素材/前端/Rust锁文件对应SBOM，逐项采集license/notice；不能把上游摘要当全量结果 |
| L02 | 同文件:23,315–317 | `github.com/Calcium-Ion/go-epay v0.0.4`标注Proprietary/Internal、归项目维护者；**不构成本仓库作者自动获许可**。复用该SDK源码/产物前核对固定版本原许可证及授权主体；若重写支付协议仍须核查协议/测试素材来源与条款 |
| L03 | 同文件:48–49,148–150；apps/api/main.go:87–88 | sing/sing-box标GPL-3.0，清单声称“隔离egress进程”且TODO；实际入口在退出时释放进程内 sing-box 拨号器，并非启动时禁用；实际版本与许可证核查见 license-dependency-review.md。不能沿用进程隔离结论；核实实际链接/分发形态、GPL与AGPL结合要求，交维护者决定 |
| L04 | NOTICE:39–50 | AWS SDK、smithy-go、otp的Apache NOTICE需保留；依赖替换后按实际产物更新，不擅删历史来源 |
| L05 | THIRD-PARTY-LICENSES.md:80–81,304–313 | Lora/Public Sans字体OFL及保留字体名、版权需随素材保留，单有外链不等于bundle中附齐文本 |
| L06 | 同文件:6；实际目录apps/api、apps/web | 上游文档仍称go.mod/web/package.json，目录已重构。依赖版本必须与固定提交实际manifest/lock核对，当前未完成 |
| L07 | 同文件:33,100及双许可证条目 | MySQL驱动MPL-2.0、DOMPurify双许可等不可简单归入MIT。按实际复用文件/依赖版本确认选用许可证及源码义务 |
| L08 | Rust Cargo.lock尚未冻结 | Rust新增依赖与其传递依赖尚无许可证清单；不能宣称已有THIRD-PARTY-LICENSES覆盖Rust版本 |

## 5. 数据库与证据限制

数据、迁移、任务、配置和外部依赖详情见同目录`data-jobs-inventory.md`。重要范围发现：SQLite/MySQL/PostgreSQL之外，源码支持ClickHouse日志库、TimescaleDB日志超表；应提交主计划变更审议，不得静默省略。

MySQL≥5.7.8、PostgreSQL≥9.6是上游README声明，不是本次执行结果；SQLite及其他服务最低版本待确认。P0要求的全字段schema、全配置键、完整后台任务全集及适配器清单尚未闭环，不能宣称完整。

## 6. 操作记录与远程验证交接

本轮仅做文件阅读/静态搜索、上述git只读检查、文档写入和三个法律文件原样复制；没有本地构建/测试/服务/容器，没有运行自写脚本，没有提交或推送，没有触发远程Actions。未改主计划。

集成者远程验证应在新仓库Actions以最小只读权限检出上游精确SHA，完成以下工作（本代理未执行）：

1. 用固定Git blob与新仓库三份法律文件做逐字节比对，记录SHA与校验结果；保留原始上游清单并另建实际Rust发行清单，不覆盖来源证据。
2. 从实际go.mod/go.sum、前端manifest/lock、Cargo.lock提取直接和传递依赖，下载固定版本法律文本进行人工复核；检查epay许可证来源及sing-box真实构建链接边界。工具报告不是法律授权替代品。
3. 对将要复用的前端、字体、图标、测试fixture、协议数据逐项记录原路径、版本、许可证、修改说明；fixture确保脱敏。不上传生产数据或密钥至公共报告/第三方评审服务。
4. 按主计划跑Go基线及数据库矩阵，产出workflow run ID、目标及上游SHA、环境版本、退出码和测试/跳过数；独立verification给结论。本轮无run ID，不能伪填PASS。
5. P8/P9在实际bundle、容器和二进制分发目录检查NOTICE、许可证、对应源代码入口和UI署名，而不是只验证仓库根存在文件。

需维护者/用户确认：ClickHouse/Timescale支持范围修订、许可不明依赖的处理方式、未确认最低数据库版本的证据或显式豁免。任何豁免未批准前相关条目保持受阻。
