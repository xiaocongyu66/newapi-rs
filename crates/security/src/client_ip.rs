//! 受信代理策略与客户端 IP 解析，移植自 Go 端 `trust_proxies.go` 的
//! `ConfigureTrustedProxies` 与 `fiberadapter/router.go` 的
//! `resolveTrustedClientIP`/`walkForwardedChain`。
//! 纯判定逻辑：不读环境变量，也不接触 HTTP 上下文；环境变量与请求头的
//! 取值由服务装配层负责，本模块只给出与 Go 一致的答案。

use std::error::Error;
use std::fmt;
use std::net::IpAddr;

/// TRUSTED_PROXIES 未设置或为空白时生效的默认网段，与 Go 逐一相同：
/// 回环、RFC 1918 与 IPv6 ULA。
const DEFAULT_TRUSTED_PROXIES: [&str; 6] = [
    "127.0.0.0/8",
    "::1",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
];

/// TRUSTED_PROXIES 的配置错误，只报分类，Display 不携带任何输入值文本。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyConfigError {
    /// 条目不是合法的 IP 或 CIDR。
    InvalidAddress,
    /// none 与其他值混用。
    NoneMustBeAlone,
    /// 逗号切分并跳过空段后没有任何条目。
    Empty,
}

impl fmt::Display for ProxyConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 文案对齐 Go 端错误串；用户输入可能包含内部拓扑，一律不回显。
        match self {
            Self::InvalidAddress => {
                f.write_str("TRUSTED_PROXIES contains an invalid IP address or CIDR")
            }
            Self::NoneMustBeAlone => f.write_str("TRUSTED_PROXIES=none must be used alone"),
            Self::Empty => f.write_str("TRUSTED_PROXIES does not contain an IP address or CIDR"),
        }
    }
}

impl Error for ProxyConfigError {}

/// 手写前缀匹配的一条网段。`ipnet` 虽已是本 crate 依赖，但按移植约定
/// 匹配逻辑自行实现，以便逐条对齐 Go `net.ParseCIDR` 与
/// `net.IPNet.Contains`（含 `networkNumberAndMask`）的行为。
#[derive(Clone, Copy, Eq, PartialEq)]
enum Network {
    /// v4 文本写法（点分十进制），前缀上限 32，`masked` 已按前缀掩码。
    V4 { masked: u32, prefix: u8 },
    /// v6 文本写法（含 `::ffff:` 映射形态），前缀上限 128，
    /// `masked` 是 128 位形态下已按前缀掩码的网络。
    V6 { masked: u128, prefix: u8 },
}

impl Network {
    fn parse(text: &str) -> Result<Self, ProxyConfigError> {
        // Go 的 ParseCIDR 按第一个斜杠切出地址与前缀，前缀必须是纯十进制
        // 数字；出现两个斜杠时 Go 的前缀段含斜杠而失败，这里按最后一个
        // 斜杠切分则地址段含斜杠而失败，多斜杠输入在两边同样被拒绝。
        let (address, prefix) = text
            .rsplit_once('/')
            .ok_or(ProxyConfigError::InvalidAddress)?;
        if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ProxyConfigError::InvalidAddress);
        }
        let prefix: u32 = prefix
            .parse()
            .map_err(|_| ProxyConfigError::InvalidAddress)?;
        // 前缀上限取 Go 的 netip.BitLen 语义：纯 v4 文本 BitLen 为 32，
        // 而 "::ffff:a.b.c.d" 在 Go 中是 Is4In6，BitLen 为 128——因此
        // "10.0.0.0/33" 非法而 "::ffff:10.0.0.0/104" 合法，此处不预先
        // 降级地址，按原始文本形态定上限。
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| ProxyConfigError::InvalidAddress)?;
        // Go 的 ParseCIDR 会 Masked() 非规范网段，此处同样先掩码。
        Ok(match address {
            IpAddr::V4(address) if prefix <= 32 => Network::V4 {
                masked: u32::from(address) & mask32(prefix),
                prefix: prefix as u8,
            },
            IpAddr::V6(address) if prefix <= 128 => Network::V6 {
                masked: u128::from(address) & mask128(prefix),
                prefix: prefix as u8,
            },
            _ => return Err(ProxyConfigError::InvalidAddress),
        })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        // Go 的 Contains 先把候选 To4 降级，再要求网络与候选的字节长度
        // 一致；v4 网段绝不匹配纯 v6 地址，反之亦然。
        let candidate = demap_v4(ip);
        match self {
            Self::V4 { masked, prefix } => match candidate {
                IpAddr::V4(ip) => u32::from(ip) & mask32(u32::from(*prefix)) == *masked,
                IpAddr::V6(_) => false,
            },
            Self::V6 { masked, prefix } => {
                // 网络降级后仍是 4 字节形态时，Go 的 networkNumberAndMask
                // 把 16 字节掩码截成 m[12:]，即有效前缀为 prefix-96（不足
                // 则整段掩码为零，匹配任意 v4 地址）；否则网络留在 v6 空间。
                let network = IpAddr::from(*masked);
                if let IpAddr::V4(masked_v4) = demap_v4(network) {
                    match candidate {
                        IpAddr::V4(ip) => {
                            let effective = u32::from(*prefix).saturating_sub(96);
                            u32::from(ip) & mask32(effective) == u32::from(masked_v4)
                        }
                        IpAddr::V6(_) => false,
                    }
                } else {
                    match candidate {
                        IpAddr::V6(ip) => {
                            u128::from(ip) & mask128(u32::from(*prefix)) == *masked
                        }
                        IpAddr::V4(_) => false,
                    }
                }
            }
        }
    }
}

fn mask32(prefix: u32) -> u32 {
    if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    }
}

fn mask128(prefix: u32) -> u128 {
    if prefix == 0 {
        0
    } else {
        !0u128 << (128 - prefix)
    }
}

fn parse_address(text: &str) -> Result<IpAddr, ProxyConfigError> {
    text.parse::<IpAddr>()
        .map(demap_v4)
        .map_err(|_| ProxyConfigError::InvalidAddress)
}

/// Go 的 `net.ParseIP` 把 "::ffff:a.b.c.d" 解析为 16 字节但 `To4` 返回
/// 4 字节，于是 v4 的网段与精确地址都能匹配它；Rust 的 `IpAddr` 保留
/// `V6` 形态，因此在入口处手工做同样的降级。只降级 `::ffff:` 映射，
/// `::` 前缀的 v4 兼容地址不降级，与 Go `To4` 一致。
///
/// 除此之外两种解析器语义核对一致：都接受 "1.2.3.4"、"::1"、
/// "::ffff:1.2.3.4" 与点分尾段写法，都拒绝 IPv4 前导零八位组、
/// "%zone" 后缀和多出的分段，故除映射降级外无需其他适配。
fn demap_v4(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
    }
}

/// 引擎的代理策略：peer 或转发链上的地址是否可信由它回答。
/// 不含任何秘密，可信地址是运维拓扑而非凭据。
#[derive(Clone, Default, Eq, PartialEq)]
pub struct ProxyPolicy {
    exact: Vec<IpAddr>,
    ranges: Vec<Network>,
}

impl ProxyPolicy {
    /// 解析 TRUSTED_PROXIES 原始值，完全复刻 Go 的 `ConfigureTrustedProxies`
    /// 加 `parseProxyPolicy`：未设置或 trim 后为空 → 默认网段；大小写不敏感
    /// 的 "none" → 不信任任何代理；否则逗号分隔 IP/CIDR，trim 后空段跳过，
    /// 混入的 "none"、全空列表与非法地址都返回错误。
    pub fn parse_trusted_proxies(raw: Option<&str>) -> Result<Self, ProxyConfigError> {
        let raw = raw.unwrap_or("").trim();
        if raw.is_empty() {
            return Self::from_entries(DEFAULT_TRUSTED_PROXIES.iter().copied());
        }
        if raw.eq_ignore_ascii_case("none") {
            // Go 端 TrustProxies(nil)：策略为 nil，trusted 恒假。
            return Ok(Self::default());
        }
        let mut entries = Vec::new();
        for part in raw.split(',') {
            let entry = part.trim();
            if entry.is_empty() {
                continue;
            }
            if entry.eq_ignore_ascii_case("none") {
                return Err(ProxyConfigError::NoneMustBeAlone);
            }
            entries.push(entry);
        }
        if entries.is_empty() {
            return Err(ProxyConfigError::Empty);
        }
        Self::from_entries(entries.iter().copied())
    }

    fn from_entries<'a>(
        entries: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, ProxyConfigError> {
        let mut policy = Self::default();
        for entry in entries {
            // 与 Go 相同：含斜杠走 CIDR，否则按裸 IP 精确匹配存储。
            if entry.contains('/') {
                policy.ranges.push(Network::parse(entry)?);
            } else {
                policy.exact.push(parse_address(entry)?);
            }
        }
        Ok(policy)
    }

    /// 该地址能否为转发头背书。空策略（none）谁都不信，peer 为任何值都返回假。
    pub fn trusts(&self, ip: IpAddr) -> bool {
        let ip = demap_v4(ip);
        self.exact.iter().any(|exact| *exact == ip)
            || self.ranges.iter().any(|range| range.contains(ip))
    }
}

/// 复刻 Go 的 `resolveTrustedClientIP`：peer 不可信时转发头一律不看，
/// 直接返回 peer；peer 可信时按 X-Forwarded-For、X-Real-IP 的顺序走
/// 转发链，右起第一个"不可信或已是最左项"的地址胜出；两个头都不可用
/// 时回落到 peer。
///
/// `peer` 为 `None` 对应 Go 端 `RemoteIP` 解析失败（如 "unknown"），
/// 返回空串。两个头参数传原始头值，`None`（头缺失）与 `Some("")`
/// （Go 的 `c.Get` 空串）等价跳过。返回胜出条目的 trim 后原文，与 Go
/// 返回 `item` 而非规范化字符串一致；只有回落 peer 才返回规范化文本。
pub fn resolve_client_ip(
    peer: Option<IpAddr>,
    forwarded_for: Option<&str>,
    real_ip: Option<&str>,
    policy: &ProxyPolicy,
) -> String {
    // Go 端 peer 是 net.IP，v4 映射地址的 String() 打印为点分十进制；
    // 这里先做同样的降级再回落输出。
    let Some(peer) = peer.map(demap_v4) else {
        return String::new();
    };
    if !policy.trusts(peer) {
        return peer.to_string();
    }
    for header in [forwarded_for, real_ip] {
        if let Some(client) = walk_forwarded_chain(header, policy) {
            return client;
        }
    }
    peer.to_string()
}

/// 复刻 Go 的 `walkForwardedChain`：逗号切分后从右往左；每项 trim 后
/// 解析，任何一项解析失败都放弃整个头（链上任一环不可考证就无法继续
/// 推断），而不是跳过该项。
fn walk_forwarded_chain(header: Option<&str>, policy: &ProxyPolicy) -> Option<String> {
    let header = header?;
    if header.is_empty() {
        return None;
    }
    let items: Vec<&str> = header.split(',').collect();
    for index in (0..items.len()).rev() {
        let item = items[index].trim();
        let Ok(parsed) = parse_address(item) else {
            break;
        };
        if index == 0 || !policy.trusts(parsed) {
            return Some(item.to_owned());
        }
    }
    None
}
