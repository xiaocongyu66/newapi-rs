//! Go `internal/usage/insight/client.go` + `discover.go` 的移植。
//!
//! `ResolveClient` 是画像分析与 InsightClientBan 中间件共用的客户端识别入口：
//! 内置规则优先（UA/专属头/提示词标记，命中即停）；未命中或命中通用 HTTP 栈
//! 时走自动发现（`ua:<token>[+<vendor>]`）。

use std::sync::OnceLock;

use regex::Regex;

/// Go `Kind*` 常量（insight/types.go:106-121）。
pub mod kind {
    pub const AGENT_CLI: &str = "agent_cli";
    pub const IDE: &str = "ide";
    pub const CHAT_UI: &str = "chat_ui";
    pub const MOBILE: &str = "mobile";
    pub const SDK: &str = "sdk";
    pub const HTTP_TOOL: &str = "http_tool";
    pub const BROWSER: &str = "browser";
    pub const DISCOVERED: &str = "discovered";
    pub const UNKNOWN: &str = "unknown";
}

/// Go `DiscoveredClientID`。
pub const DISCOVERED_CLIENT_ID: &str = "ua:";
const MAX_DISCOVERED_TOKEN_LEN: usize = 32;

/// Go `clientRule`。`ua_regex` 是 UA 子串命中后的硬性边界约束；
/// `version_from`："ua" 表示从 UA 提取版本，其他值是 header 名。
#[derive(Debug)]
struct ClientRule {
    id: &'static str,
    name: &'static str,
    kind: &'static str,
    ua_substrings: &'static [&'static str],
    ua_regex: Option<&'static str>,
    header_keys: &'static [&'static str],
    header_pairs: &'static [(&'static str, &'static str)],
    prompt_markers: &'static [&'static str],
    version_from: &'static str,
}

/// Go `clientRules`：44 条，按优先级从具体到宽泛排列，命中即停。
/// 浏览器兜底规则（mozilla/5.0 等宽泛特征）必须垫底。
static CLIENT_RULES: &[ClientRule] = &[
    ClientRule {
        id: "claude_code",
        name: "Claude Code",
        kind: kind::AGENT_CLI,
        ua_substrings: &["claude-cli", "claude-code"],
        ua_regex: None,
        header_keys: &["X-App", "Anthropic-Beta"],
        header_pairs: &[("X-App", "cli")],
        prompt_markers: &[
            "you are claude code",
            "anthropic's official cli",
            "claude code, anthropic's",
            "# claude.md",
            "<system-reminder>",
            "str_replace_editor",
            "todowrite",
        ],
        version_from: "ua",
    },
    ClientRule {
        id: "codex_cli",
        name: "Codex CLI",
        kind: kind::AGENT_CLI,
        ua_substrings: &["codex_cli_rs", "codex-cli", "codex/", "codex desktop"],
        ua_regex: None,
        header_keys: &["Originator", "Session_id", "Openai-Beta"],
        header_pairs: &[("Originator", "codex_cli_rs")],
        prompt_markers: &[
            "you are a coding agent running in the codex cli",
            "you are codex, based on gpt-5",
            "codex cli",
            "apply_patch",
            "*** begin patch",
            "shell(command",
            "# sandboxing and approvals",
        ],
        version_from: "ua",
    },
    ClientRule {
        id: "opencode",
        name: "OpenCode",
        kind: kind::AGENT_CLI,
        ua_substrings: &["opencode"],
        ua_regex: None,
        header_keys: &["X-Opencode-Version", "X-Opencode"],
        header_pairs: &[],
        prompt_markers: &[
            "you are opencode",
            "opencode, an autonomous",
            "agents.md",
            "you are a coding agent built by sst",
            "opencode.ai",
        ],
        version_from: "X-Opencode-Version",
    },
    ClientRule {
        id: "zcode",
        name: "ZCode",
        kind: kind::AGENT_CLI,
        ua_substrings: &["zcode", "z-code", "zai-code", "glm-code"],
        ua_regex: None,
        header_keys: &["X-Zcode-Version", "X-Z-Client"],
        header_pairs: &[],
        prompt_markers: &["you are zcode", "zcode cli", "z.ai code", "你是 zcode"],
        version_from: "ua",
    },
    ClientRule {
        id: "gemini_cli",
        name: "Gemini CLI",
        kind: kind::AGENT_CLI,
        ua_substrings: &["gemini-cli", "genai-js", "google-genai"],
        ua_regex: None,
        header_keys: &["X-Goog-Api-Client"],
        header_pairs: &[],
        prompt_markers: &[
            "you are an interactive cli agent",
            "gemini.md",
            "you are a cli agent specializing in software engineering",
        ],
        version_from: "ua",
    },
    ClientRule {
        id: "cline",
        name: "Cline",
        kind: kind::IDE,
        ua_substrings: &["cline/", "cline-vscode"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[
            "you are cline",
            "cline, a highly skilled software engineer",
            "replace_in_file",
            "environment_details",
        ],
        version_from: "",
    },
    ClientRule {
        id: "roo_code",
        name: "Roo Code",
        kind: kind::IDE,
        ua_substrings: &["roo-code", "roocode", "roo-cline"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &["you are roo", "roo code", "apply_diff"],
        version_from: "",
    },
    ClientRule {
        id: "kilo_code",
        name: "Kilo Code",
        kind: kind::IDE,
        ua_substrings: &["kilocode", "kilo-code"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &["you are kilo code", "kilocode"],
        version_from: "",
    },
    ClientRule {
        id: "cursor",
        name: "Cursor",
        kind: kind::IDE,
        ua_substrings: &["cursor"],
        ua_regex: None,
        header_keys: &["X-Cursor-Client-Version", "X-Cursor-Checksum"],
        header_pairs: &[],
        prompt_markers: &[
            "you are a powerful agentic ai coding assistant, powered by",
            "you are pair programming with a user in cursor",
            "cursor ide",
            "<edit_file>",
        ],
        version_from: "X-Cursor-Client-Version",
    },
    ClientRule {
        id: "windsurf",
        name: "Windsurf",
        kind: kind::IDE,
        ua_substrings: &["windsurf", "codeium"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[
            "you are cascade",
            "windsurf, the world's first agentic ide",
            "cascade, a powerful agentic ai coding assistant",
        ],
        version_from: "",
    },
    ClientRule {
        id: "copilot",
        name: "GitHub Copilot",
        kind: kind::IDE,
        ua_substrings: &["githubcopilot", "copilot-", "vscode-copilot"],
        ua_regex: None,
        header_keys: &["Copilot-Integration-Id", "Editor-Version"],
        header_pairs: &[],
        prompt_markers: &[
            "you are github copilot",
            "you are an ai programming assistant",
            "when asked for your name, you must respond with \"github copilot\"",
        ],
        version_from: "Editor-Version",
    },
    ClientRule {
        id: "continue",
        name: "Continue",
        kind: kind::IDE,
        ua_substrings: &["continue/", "continuedev"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &["you are an expert software developer", "continue.dev"],
        version_from: "",
    },
    ClientRule {
        id: "aider",
        name: "Aider",
        kind: kind::AGENT_CLI,
        ua_substrings: &["aider"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[
            "act as an expert software developer",
            "always use best practices when coding",
            "search/replace block",
            "<<<<<<< search",
        ],
        version_from: "",
    },
    ClientRule {
        id: "crush",
        name: "Crush",
        kind: kind::AGENT_CLI,
        ua_substrings: &["crush", "charmbracelet"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &["you are crush", "crush, an autonomous coding agent"],
        version_from: "",
    },
    // 绝不能收裸 "droid"：它是 "Android" 的子串，会误认安卓端请求。
    ClientRule {
        id: "droid",
        name: "Factory Droid",
        kind: kind::AGENT_CLI,
        ua_substrings: &["factory-cli", "factory.ai", "factorydroid"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[
            "you are droid",
            "factory.ai",
            "you are a droid built by factory",
        ],
        version_from: "",
    },
    // 绝不能收裸 "pi/"："api/0.1" 这类网关 UA 是它的超集；词边界校验。
    ClientRule {
        id: "pi",
        name: "Pi",
        kind: kind::AGENT_CLI,
        ua_substrings: &["pi/0.", "pi/1.", "pi-cli", "pi-mono", "pi-agent"],
        ua_regex: Some(r"(^|[^a-z0-9])pi/"),
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[],
        version_from: "ua",
    },
    ClientRule {
        id: "oh_my_pi",
        name: "Oh My Pi",
        kind: kind::AGENT_CLI,
        ua_substrings: &["oh-my-pi"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[],
        version_from: "ua",
    },
    ClientRule {
        id: "qwen_code",
        name: "QwenCode",
        kind: kind::AGENT_CLI,
        ua_substrings: &["qwencode", "qwen-code", "qwen_cli"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[],
        version_from: "ua",
    },
    ClientRule {
        id: "sillytavern",
        name: "SillyTavern",
        kind: kind::CHAT_UI,
        ua_substrings: &["sillytavern", "silly-tavern", "tauritavern"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[
            "[start a new chat]",
            "write {{char}}'s next reply",
            "{{char}}",
            "{{user}}",
            "you are {{char}}",
            "[system note:",
            "jailbreak",
            "nsfwprompt",
        ],
        version_from: "",
    },
    ClientRule {
        id: "rikkahub",
        name: "RikkaHub",
        kind: kind::MOBILE,
        ua_substrings: &["rikkahub"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[],
        version_from: "ua",
    },
    ClientRule {
        id: "tavo",
        name: "Tavo",
        kind: kind::MOBILE,
        ua_substrings: &["tavo/", "tavoai.dev"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[],
        version_from: "ua",
    },
    ClientRule {
        id: "kelivo",
        name: "Kelivo",
        kind: kind::MOBILE,
        ua_substrings: &["kelivo"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[],
        version_from: "",
    },
    ClientRule {
        id: "vercel_ai_sdk",
        name: "Vercel AI SDK",
        kind: kind::SDK,
        ua_substrings: &["ai-sdk/"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[],
        version_from: "ua",
    },
    ClientRule {
        id: "cherry_studio",
        name: "Cherry Studio",
        kind: kind::CHAT_UI,
        ua_substrings: &["cherrystudio", "cherry-studio"],
        ua_regex: None,
        header_keys: &["X-Cherry-Version"],
        header_pairs: &[],
        prompt_markers: &["cherry studio"],
        version_from: "X-Cherry-Version",
    },
    ClientRule {
        id: "chatbox",
        name: "Chatbox",
        kind: kind::CHAT_UI,
        ua_substrings: &["chatbox"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[],
        version_from: "",
    },
    ClientRule {
        id: "lobechat",
        name: "LobeChat",
        kind: kind::CHAT_UI,
        ua_substrings: &["lobechat", "lobe-chat"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &["lobechat"],
        version_from: "",
    },
    ClientRule {
        id: "openwebui",
        name: "Open WebUI",
        kind: kind::CHAT_UI,
        ua_substrings: &["open-webui", "openwebui"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[
            "### task:\ngenerate",
            "### task:\ncreate a concise",
            "chat history:\n<chat_history>",
        ],
        version_from: "",
    },
    ClientRule {
        id: "nextchat",
        name: "NextChat",
        kind: kind::CHAT_UI,
        ua_substrings: &["nextchat", "chatgpt-next-web"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[],
        version_from: "",
    },
    ClientRule {
        id: "immersive_translate",
        name: "Immersive Translate",
        kind: kind::SDK,
        ua_substrings: &["immersivetranslate", "immersive-translate"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[
            "you are a professional, authentic machine translation engine",
            "translate the following source text to",
        ],
        version_from: "",
    },
    ClientRule {
        id: "openai_sdk",
        name: "OpenAI SDK",
        kind: kind::SDK,
        ua_substrings: &["openai-python", "openai-node", "openai/"],
        ua_regex: None,
        header_keys: &["X-Stainless-Lang", "X-Stainless-Package-Version"],
        header_pairs: &[],
        prompt_markers: &[],
        version_from: "X-Stainless-Package-Version",
    },
    ClientRule {
        id: "anthropic_sdk",
        name: "Anthropic SDK",
        kind: kind::SDK,
        ua_substrings: &["anthropic-python", "anthropic-sdk", "anthropic-ai"],
        ua_regex: None,
        header_keys: &["X-Stainless-Lang"],
        header_pairs: &[],
        prompt_markers: &[],
        version_from: "X-Stainless-Package-Version",
    },
    ClientRule {
        id: "langchain",
        name: "LangChain",
        kind: kind::SDK,
        ua_substrings: &["langchain", "langgraph", "llamaindex"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[],
        version_from: "",
    },
    // HTTP 工具逐个独立成条：封禁要能"分别处置 curl 与 okhttp"。
    ClientRule {
        id: "curl",
        name: "curl",
        kind: kind::HTTP_TOOL,
        ua_substrings: &["curl/"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[],
        version_from: "ua",
    },
    ClientRule {
        id: "python_requests",
        name: "Python requests",
        kind: kind::HTTP_TOOL,
        ua_substrings: &["python-requests"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[],
        version_from: "ua",
    },
    ClientRule {
        id: "httpx",
        name: "httpx",
        kind: kind::HTTP_TOOL,
        ua_substrings: &["python-httpx", "httpx/"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[],
        version_from: "ua",
    },
    ClientRule {
        id: "aiohttp",
        name: "aiohttp",
        kind: kind::HTTP_TOOL,
        ua_substrings: &["aiohttp"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[],
        version_from: "ua",
    },
    ClientRule {
        id: "okhttp",
        name: "OkHttp",
        kind: kind::HTTP_TOOL,
        ua_substrings: &["okhttp"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[],
        version_from: "ua",
    },
    ClientRule {
        id: "axios",
        name: "axios",
        kind: kind::HTTP_TOOL,
        ua_substrings: &["axios"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[],
        version_from: "ua",
    },
    ClientRule {
        id: "node_fetch",
        name: "node-fetch",
        kind: kind::HTTP_TOOL,
        ua_substrings: &["node-fetch", "undici"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[],
        version_from: "ua",
    },
    ClientRule {
        id: "go_http",
        name: "Go http",
        kind: kind::HTTP_TOOL,
        ua_substrings: &["go-http-client"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[],
        version_from: "ua",
    },
    ClientRule {
        id: "deno",
        name: "Deno",
        kind: kind::HTTP_TOOL,
        ua_substrings: &["deno/"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[],
        version_from: "ua",
    },
    ClientRule {
        id: "postman",
        name: "Postman",
        kind: kind::HTTP_TOOL,
        ua_substrings: &["postman"],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[],
        version_from: "",
    },
    ClientRule {
        id: "generic_http",
        name: "Other HTTP Client",
        kind: kind::HTTP_TOOL,
        ua_substrings: &[
            "http-client",
            "libcurl",
            "urllib",
            "wget",
            "java/",
            "reqwest",
            "guzzle",
            "restsharp",
        ],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[],
        version_from: "",
    },
    // 兜底垫底：浏览器/WebView 特征宽泛。
    ClientRule {
        id: "browser",
        name: "Web Browser",
        kind: kind::BROWSER,
        ua_substrings: &[
            "mozilla/5.0",
            "safari/",
            "chrome/",
            "firefox/",
            "edg/",
            "dalvik/",
            "cfnetwork/",
        ],
        ua_regex: None,
        header_keys: &[],
        header_pairs: &[],
        prompt_markers: &[],
        version_from: "",
    },
];

/// Go `ResolveClient` 结果。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ResolvedClient {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub version: String,
    pub source: String,
    pub score: i32,
}

/// 请求头视图：服务层把 HeaderMap 折叠成小写名 → 首值的表。
pub type HeaderMapLite = std::collections::HashMap<String, String>;

fn header_get(headers: &HeaderMapLite, name: &str) -> String {
    headers
        .get(&name.to_lowercase())
        .cloned()
        .unwrap_or_default()
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

fn semver_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.-]+)?)").expect("valid semver")
    })
}

/// Go `DetectClient`（client.go:518-540）。
pub fn detect_client(headers: &HeaderMapLite, prompt: &str) -> ResolvedClient {
    let ua = header_get(headers, "User-Agent").to_lowercase();
    for rule in CLIENT_RULES {
        let header_hit = rule_matches_header(rule, headers, &ua);
        let prompt_hit = !prompt.is_empty() && contains_any(prompt, rule.prompt_markers);
        if !header_hit && !prompt_hit {
            continue;
        }
        let (source, score) = if header_hit && prompt_hit {
            ("both", 100)
        } else if header_hit {
            ("header", 85)
        } else {
            // 仅提示词命中：UA 被中转站抹掉时的主要依据。
            ("prompt", 70)
        };
        return ResolvedClient {
            id: rule.id.to_owned(),
            name: rule.name.to_owned(),
            kind: rule.kind.to_owned(),
            version: extract_client_version(rule, headers, &ua, header_hit),
            source: source.to_owned(),
            score,
        };
    }
    ResolvedClient {
        kind: kind::UNKNOWN.to_owned(),
        ..ResolvedClient::default()
    }
}

/// Go `ruleMatchesHeader`（client.go:542-561）。
fn rule_matches_header(rule: &ClientRule, headers: &HeaderMapLite, ua: &str) -> bool {
    if !ua.is_empty() && contains_any(ua, rule.ua_substrings) {
        let boundary_ok = match rule.ua_regex {
            None => true,
            Some(pattern) => Regex::new(pattern)
                .map(|re| re.is_match(ua))
                .unwrap_or(false),
        };
        if boundary_ok {
            return true;
        }
    }
    for (key, want) in rule.header_pairs {
        if header_get(headers, key)
            .to_lowercase()
            .contains(&want.to_lowercase())
        {
            return true;
        }
    }
    rule.header_keys
        .iter()
        .any(|key| !header_get(headers, key).is_empty())
}

/// Go `extractClientVersion`（client.go:563-577）。
fn extract_client_version(
    rule: &ClientRule,
    headers: &HeaderMapLite,
    ua: &str,
    header_hit: bool,
) -> String {
    if rule.version_from.is_empty() {
        return String::new();
    }
    if rule.version_from != "ua" {
        return semver_regex()
            .find(&header_get(headers, rule.version_from))
            .map(|m| m.as_str().to_owned())
            .unwrap_or_default();
    }
    // 从 UA 取版本只在 UA 确实命中该工具时可信。
    if !header_hit || !contains_any(ua, rule.ua_substrings) {
        return String::new();
    }
    semver_regex()
        .find(ua)
        .map(|m| m.as_str().to_owned())
        .unwrap_or_default()
}

/// Go `ResolveClient`（discover.go:99-113）。
pub fn resolve_client(headers: &HeaderMapLite, prompt: &str) -> ResolvedClient {
    let detected = detect_client(headers, prompt);
    if !detected.id.is_empty() && detected.kind != kind::HTTP_TOOL {
        return detected;
    }
    // 通用 HTTP 栈：确实存在工具专属头时才细分。
    if !detected.id.is_empty() && discover_vendor_header(headers).is_empty() {
        return detected;
    }
    if let Some(discovered) = discover_client(headers) {
        return ResolvedClient {
            id: discovered.0,
            name: discovered.1,
            kind: kind::DISCOVERED.to_owned(),
            version: String::new(),
            source: "header".to_owned(),
            score: 60,
        };
    }
    detected
}

/// Go `DiscoverClient`：`ua:<token>[+<vendor>]`。
pub fn discover_client(headers: &HeaderMapLite) -> Option<(String, String)> {
    let ua_token = discover_ua_token(&header_get(headers, "User-Agent"));
    let vendor_header = discover_vendor_header(headers);
    match (ua_token, vendor_header) {
        (Some(token), Some(vendor)) => Some((
            format!("{DISCOVERED_CLIENT_ID}{token}+{vendor}"),
            format!("{token} ({vendor})"),
        )),
        (Some(token), None) => Some((format!("{DISCOVERED_CLIENT_ID}{token}"), token)),
        (None, Some(vendor)) => Some((format!("{DISCOVERED_CLIENT_ID}{vendor}"), vendor)),
        (None, None) => None,
    }
}

/// Go `discoverUAToken`（discover.go:140-165）。
fn discover_ua_token(ua: &str) -> Option<String> {
    let ua = ua.trim().to_lowercase();
    if ua.is_empty() || ua == "-" {
        return None;
    }
    let mut product = ua.as_str();
    if let Some(idx) = product.find([' ', '\t']) {
        if idx > 0 {
            product = &product[..idx];
        }
    }
    if let Some(idx) = product.find('/') {
        if idx > 0 {
            product = &product[..idx];
        }
    }
    // Go uaProductRe：^([a-z0-9][a-z0-9._+-]{1,31})
    let re = ua_product_regex();
    let matched = re.find(product)?.as_str().to_owned();
    let matched = matched.trim_matches(['.', '-', '_', '+']).to_owned();
    // 纯数字或过短的 token 不具备识别价值。
    if matched.len() < 3 || !matched.chars().any(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    let truncated: String = matched.chars().take(MAX_DISCOVERED_TOKEN_LEN).collect();
    Some(truncated)
}

fn ua_product_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^([a-z0-9][a-z0-9._+-]{1,31})").expect("valid ua regex"))
}

/// Go `discoveredVendorHeaderRe`：`^x-([a-z0-9]{2,20})-`。
fn vendor_header_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^x-([a-z0-9]{2,20})-").expect("valid vendor regex"))
}

/// Go `discoveredHeaderDenyList`：中转站/CDN/标准协议头不当作工具专属头。
const DISCOVERED_HEADER_DENY_LIST: &[&str] = &[
    "forwarded",
    "real",
    "request",
    "requested",
    "correlation",
    "trace",
    "amz",
    "amzn",
    "aws",
    "goog",
    "google",
    "azure",
    "ms",
    "cache",
    "cdn",
    "cf",
    "envoy",
    "nginx",
    "varnish",
    "proxy",
    "relay",
    "upstream",
    "api",
    "auth",
    "csrf",
    "xsrf",
    "content",
    "accept",
    "frame",
    "scheme",
    "host",
    "port",
    "for",
    "stainless",
    "ratelimit",
    "rate",
    "title",
    "session",
    "user",
    "client",
    "device",
    "platform",
    "lang",
    "locale",
    "timezone",
    // 本网关自己的转发标识头。
    "oneapi",
    "newapi",
];

/// Go `discoverVendorHeader`（discover.go:168-196）：命多个取字典序最小。
fn discover_vendor_header(headers: &HeaderMapLite) -> String {
    let re = vendor_header_regex();
    let mut best = String::new();
    for key in headers.keys() {
        let lower = key.to_lowercase();
        let Some(m) = re.captures(&lower) else {
            continue;
        };
        let vendor = &m[1];
        if DISCOVERED_HEADER_DENY_LIST.contains(&vendor) {
            continue;
        }
        if builtin_header_vendors().contains(&vendor) {
            continue;
        }
        let identity = format!("x-{vendor}");
        if best.is_empty() || identity < best {
            best = identity;
        }
    }
    best
}

/// Go `builtinHeaderVendors`：内置规则已使用的 vendor 段，自动发现不再用。
fn builtin_header_vendors() -> &'static std::collections::HashSet<&'static str> {
    static SET: OnceLock<std::collections::HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| {
        let re = vendor_header_regex();
        let mut vendors = std::collections::HashSet::new();
        for rule in CLIENT_RULES {
            for key in rule.header_keys {
                if let Some(m) = re.captures(&key.to_lowercase()) {
                    vendors.insert(leak_vendor(&m[1]));
                }
            }
            for (key, _) in rule.header_pairs {
                if let Some(m) = re.captures(&key.to_lowercase()) {
                    vendors.insert(leak_vendor(&m[1]));
                }
            }
        }
        vendors
    })
}

/// 'static 泄漏：vendor 段 ≤20 字符的小集合，进程生命周期只构建一次。
fn leak_vendor(vendor: &str) -> &'static str {
    Box::leak(vendor.to_owned().into_boxed_str())
}

/// Go `IsDiscoveredClient`。
pub fn is_discovered_client(id: &str) -> bool {
    id.starts_with(DISCOVERED_CLIENT_ID)
}

/// Go `DiscoveredClientName`。
pub fn discovered_client_name(id: &str) -> String {
    if !is_discovered_client(id) {
        return id.to_owned();
    }
    let token = &id[DISCOVERED_CLIENT_ID.len()..];
    match token.split_once('+') {
        Some((ua, vendor)) => format!("{ua} ({vendor})"),
        None => token.to_owned(),
    }
}

/// Go `ClientCatalogEntry` + `ClientCatalog`。
#[derive(Clone, Debug, PartialEq)]
pub struct ClientCatalogEntry {
    pub id: String,
    pub name: String,
    pub kind: String,
}

pub fn client_catalog() -> Vec<ClientCatalogEntry> {
    CLIENT_RULES
        .iter()
        .map(|rule| ClientCatalogEntry {
            id: rule.id.to_owned(),
            name: rule.name.to_owned(),
            kind: rule.kind.to_owned(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMapLite {
        pairs
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.to_string()))
            .collect()
    }

    #[test]
    fn detects_claude_code_by_ua() {
        let client = resolve_client(
            &headers(&[("User-Agent", "claude-cli/1.2.3 (x)"), ("X-App", "cli")]),
            "",
        );
        assert_eq!(client.id, "claude_code");
        assert_eq!(client.version, "1.2.3");
        assert_eq!(client.source, "header");
        assert_eq!(client.score, 85);
    }

    #[test]
    fn pi_boundary_check() {
        // "api/0.1" 是 pi/0. 的超集，必须有词边界判定。
        let client = detect_client(&headers(&[("User-Agent", "api/0.1")]), "");
        assert_ne!(client.id, "pi");
        let client = detect_client(&headers(&[("User-Agent", "pi/0.4.1")]), "");
        assert_eq!(client.id, "pi");
    }

    #[test]
    fn browser_fallback_bottom() {
        let client = resolve_client(
            &headers(&[("User-Agent", "Mozilla/5.0 (X11) Chrome/120")]),
            "",
        );
        assert_eq!(client.id, "browser");
    }

    #[test]
    fn http_tool_with_vendor_header_prefers_discovery() {
        // okhttp 命中通用 HTTP 栈，但带工具专属头 → 以自动发现为准。
        let client = resolve_client(
            &headers(&[("User-Agent", "okhttp/4.12"), ("X-Deepseek-Version", "1.0")]),
            "",
        );
        assert_eq!(client.kind, kind::DISCOVERED);
        assert_eq!(client.id, "ua:okhttp+x-deepseek");
    }

    #[test]
    fn http_tool_without_vendor_header_stays() {
        let client = resolve_client(&headers(&[("User-Agent", "curl/8.1")]), "");
        assert_eq!(client.id, "curl");
        assert_eq!(client.kind, kind::HTTP_TOOL);
    }

    #[test]
    fn prompt_marker_hit() {
        let client = detect_client(
            &headers(&[("User-Agent", "custom-agent")]),
            "you are claude code, the terminal assistant",
        );
        assert_eq!(client.id, "claude_code");
        assert_eq!(client.source, "prompt");
        assert_eq!(client.score, 70);
    }

    #[test]
    fn deny_list_vendor_headers() {
        let client = resolve_client(
            &headers(&[
                ("User-Agent", "python-requests/2.31"),
                ("X-Cache-Backend", "edge"),
            ]),
            "",
        );
        assert_eq!(client.id, "python_requests");
    }

    #[test]
    fn oneapi_header_is_gateway_not_tool() {
        let client = resolve_client(
            &headers(&[
                ("User-Agent", "myagent/1.0"),
                ("X-Oneapi-Request-Id", "abc"),
            ]),
            "",
        );
        assert_eq!(client.id, "ua:myagent");
    }

    #[test]
    fn discovered_name_display() {
        assert_eq!(discovered_client_name("ua:okhttp+x-foo"), "okhttp (x-foo)");
        assert_eq!(discovered_client_name("ua:myagent"), "myagent");
        assert_eq!(discovered_client_name("curl"), "curl");
    }

    #[test]
    fn catalog_matches_rules_count() {
        // Go clientRules 共 44 条（任务简报口径）。
        assert_eq!(client_catalog().len(), 44);
    }

    #[test]
    fn unknown_ua_falls_to_none() {
        let client = resolve_client(&headers(&[("User-Agent", "-")]), "");
        assert_eq!(client.id, "");
        assert_eq!(client.kind, kind::UNKNOWN);
    }
}
