//! Go `internal/relay/resolve_adaptor.go` + `internal/common/api_type.go` +
//! `internal/constant/channel.go` / `api_type.go` 的移植。
//!
//! 本切片产出"适配器解析端口"：`Adaptor` trait 的接口形状与
//! `resolve_adaptor` 的注册表。openai / claude / gemini 的外呼实现位于
//! [`crate::adaptors`]（channel-adapter 切片），其余 45 个适配器后续落地时
//! 逐个实现本 trait；未移植者继承 trait 的默认 `do_request`（错误占位）。

use std::future::Future;
use std::pin::Pin;

/// Go `constant.APIType*`（api_type.go iota 序号，逐项对齐）。
pub mod api_type {
    pub const OPENAI: i32 = 0;
    pub const ANTHROPIC: i32 = 1;
    pub const PALM: i32 = 2;
    pub const BAIDU: i32 = 3;
    pub const ZHIPU: i32 = 4;
    pub const ALI: i32 = 5;
    pub const XUNFEI: i32 = 6;
    pub const AI_PROXY_LIBRARY: i32 = 7;
    pub const TENCENT: i32 = 8;
    pub const GEMINI: i32 = 9;
    pub const ZHIPU_V4: i32 = 10;
    pub const OLLAMA: i32 = 11;
    pub const PERPLEXITY: i32 = 12;
    pub const AWS: i32 = 13;
    pub const COHERE: i32 = 14;
    pub const DIFY: i32 = 15;
    pub const JINA: i32 = 16;
    pub const CLOUDFLARE: i32 = 17;
    pub const SILICON_FLOW: i32 = 18;
    pub const VERTEX_AI: i32 = 19;
    pub const MISTRAL: i32 = 20;
    pub const DEEP_SEEK: i32 = 21;
    pub const MOKA_AI: i32 = 22;
    pub const VOLC_ENGINE: i32 = 23;
    pub const BAIDU_V2: i32 = 24;
    pub const OPEN_ROUTER: i32 = 25;
    pub const XINFERENCE: i32 = 26;
    pub const XAI: i32 = 27;
    pub const COZE: i32 = 28;
    pub const JIMENG: i32 = 29;
    pub const MOONSHOT: i32 = 30;
    pub const SUBMODEL: i32 = 31;
    pub const MINI_MAX: i32 = 32;
    pub const REPLICATE: i32 = 33;
    pub const CODEX: i32 = 34;
    pub const ADVANCED_CUSTOM: i32 = 35;
    pub const SUB2API: i32 = 36;
    pub const NEW_API: i32 = 37;
    pub const DUMMY: i32 = 38;
}

/// Go `constant.ChannelType*`（channel.go 逐项对齐）。
pub mod channel_type {
    pub const UNKNOWN: i32 = 0;
    pub const OPENAI: i32 = 1;
    pub const MIDJOURNEY: i32 = 2;
    pub const AZURE: i32 = 3;
    pub const OLLAMA: i32 = 4;
    pub const MIDJOURNEY_PLUS: i32 = 5;
    pub const OPENAI_MAX: i32 = 6;
    pub const OH_MY_GPT: i32 = 7;
    pub const CUSTOM: i32 = 8;
    pub const AILS: i32 = 9;
    pub const AI_PROXY: i32 = 10;
    pub const PALM: i32 = 11;
    pub const API2GPT: i32 = 12;
    pub const AIGC2D: i32 = 13;
    pub const ANTHROPIC: i32 = 14;
    pub const BAIDU: i32 = 15;
    pub const ZHIPU: i32 = 16;
    pub const ALI: i32 = 17;
    pub const XUNFEI: i32 = 18;
    #[allow(non_upper_case_globals)]
    pub const CHANNEL_TYPE_360: i32 = 19;
    pub const OPEN_ROUTER: i32 = 20;
    pub const AI_PROXY_LIBRARY: i32 = 21;
    pub const FAST_GPT: i32 = 22;
    pub const TENCENT: i32 = 23;
    pub const GEMINI: i32 = 24;
    pub const MOONSHOT: i32 = 25;
    pub const ZHIPU_V4: i32 = 26;
    pub const PERPLEXITY: i32 = 27;
    pub const LING_YI_WAN_WU: i32 = 31;
    pub const AWS: i32 = 33;
    pub const COHERE: i32 = 34;
    pub const MINI_MAX: i32 = 35;
    pub const SUNO_API: i32 = 36;
    pub const DIFY: i32 = 37;
    pub const JINA: i32 = 38;
    pub const CLOUDFLARE: i32 = 39;
    pub const SILICON_FLOW: i32 = 40;
    pub const VERTEX_AI: i32 = 41;
    pub const MISTRAL: i32 = 42;
    pub const DEEP_SEEK: i32 = 43;
    pub const MOKA_AI: i32 = 44;
    pub const VOLC_ENGINE: i32 = 45;
    pub const BAIDU_V2: i32 = 46;
    pub const XINFERENCE: i32 = 47;
    pub const XAI: i32 = 48;
    pub const COZE: i32 = 49;
    pub const KLING: i32 = 50;
    pub const JIMENG: i32 = 51;
    pub const VIDU: i32 = 52;
    pub const SUBMODEL: i32 = 53;
    pub const DOUBAO_VIDEO: i32 = 54;
    pub const SORA: i32 = 55;
    pub const REPLICATE: i32 = 56;
    pub const CODEX: i32 = 57;
    pub const ADVANCED_CUSTOM: i32 = 58;
    pub const SUB2API: i32 = 59;
    pub const NEW_API: i32 = 60;
    pub const DUMMY: i32 = 61;
}

/// Go `common.ChannelType2APIType`（api_type.go:5-89）。未映射的渠道返回
/// `(APITypeOpenAI, false)`——与 Go 的 `-1 → (OpenAI, false)` 语义一致。
pub fn channel_type_to_api_type(channel_type: i32) -> (i32, bool) {
    // 通过完整路径引用两个常量模块，避免 glob 歧义。
    let api_type = match channel_type {
        channel_type::OPENAI => api_type::OPENAI,
        channel_type::ANTHROPIC => api_type::ANTHROPIC,
        channel_type::BAIDU => api_type::BAIDU,
        channel_type::PALM => api_type::PALM,
        channel_type::ZHIPU => api_type::ZHIPU,
        channel_type::ALI => api_type::ALI,
        channel_type::XUNFEI => api_type::XUNFEI,
        channel_type::AI_PROXY_LIBRARY => api_type::AI_PROXY_LIBRARY,
        channel_type::TENCENT => api_type::TENCENT,
        channel_type::GEMINI => api_type::GEMINI,
        channel_type::ZHIPU_V4 => api_type::ZHIPU_V4,
        channel_type::OLLAMA => api_type::OLLAMA,
        channel_type::PERPLEXITY => api_type::PERPLEXITY,
        channel_type::AWS => api_type::AWS,
        channel_type::COHERE => api_type::COHERE,
        channel_type::DIFY => api_type::DIFY,
        channel_type::JINA => api_type::JINA,
        channel_type::CLOUDFLARE => api_type::CLOUDFLARE,
        channel_type::SILICON_FLOW => api_type::SILICON_FLOW,
        channel_type::VERTEX_AI => api_type::VERTEX_AI,
        channel_type::MISTRAL => api_type::MISTRAL,
        channel_type::DEEP_SEEK => api_type::DEEP_SEEK,
        channel_type::MOKA_AI => api_type::MOKA_AI,
        channel_type::VOLC_ENGINE => api_type::VOLC_ENGINE,
        channel_type::BAIDU_V2 => api_type::BAIDU_V2,
        channel_type::OPEN_ROUTER => api_type::OPEN_ROUTER,
        channel_type::XINFERENCE => api_type::XINFERENCE,
        channel_type::XAI => api_type::XAI,
        channel_type::COZE => api_type::COZE,
        channel_type::JIMENG => api_type::JIMENG,
        channel_type::MOONSHOT => api_type::MOONSHOT,
        channel_type::SUBMODEL => api_type::SUBMODEL,
        channel_type::MINI_MAX => api_type::MINI_MAX,
        channel_type::REPLICATE => api_type::REPLICATE,
        channel_type::CODEX => api_type::CODEX,
        channel_type::ADVANCED_CUSTOM => api_type::ADVANCED_CUSTOM,
        channel_type::SUB2API => api_type::SUB2API,
        channel_type::NEW_API => api_type::NEW_API,
        _ => -1,
    };
    if api_type == -1 {
        (api_type::OPENAI, false)
    } else {
        (api_type, true)
    }
}

/// Go `common.IsResponsesCompactAPIType`（api_type.go:91-102）。
pub fn is_responses_compact_api_type(api_type: i32) -> bool {
    matches!(
        api_type,
        api_type::OPENAI
            | api_type::CODEX
            | api_type::ADVANCED_CUSTOM
            | api_type::SUB2API
            | api_type::NEW_API
    )
}

/// 适配器实现的占位枚举：与 Go `GetAdaptor` 返回的具体类型一一对应。
/// dispatch 切片为每个 Kind 提供真实外呼实现后，注册表下沉。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdaptorKind {
    Ali,
    Anthropic,
    Baidu,
    Gemini,
    OpenAI,
    Palm,
    Tencent,
    Xunfei,
    Zhipu,
    ZhipuV4,
    Ollama,
    Perplexity,
    Aws,
    Cohere,
    Dify,
    Jina,
    Cloudflare,
    SiliconFlow,
    VertexAi,
    Mistral,
    DeepSeek,
    MokaAi,
    VolcEngine,
    BaiduV2,
    /// OpenRouter / Xinference 复用 OpenAI 适配器（Go `&openai.Adaptor{}`）。
    OpenAiCompat,
    Xai,
    Coze,
    Jimeng,
    Moonshot,
    Submodel,
    MiniMax,
    Replicate,
    Codex,
    AdvancedCustom,
    Sub2Api,
    NewApi,
}

/// Go `channel.Adaptor`（channel/adapter.go:16-33）的 trait 端口。
///
/// 接口形状逐方法对齐；请求/响应载荷在 Rust 侧统一用 `serde_json::Value`
/// 表示（Go 的 `any` 转换产物）。`Context` 是服务装配层注入的抽象，
/// 纯 crate 内不持有 HTTP 状态，因此 `SetupRequestHeader` 的输出是
/// 应写入的 header 集合而非直改外部对象。
///
/// 本切片（channel-adapter）扩展的接口形状（合并时主控协调）：
/// - `do_request`：Go 的 `DoRequest` 完成真实外呼并返回响应。Rust 侧外呼经
///   [`crate::adaptor_common::OutboundTransport`] 注入（生产 reqwest、测试
///   替身），方法签名携带 transport 并返回
///   `Pin<Box<dyn Future<...>>>`（`apps/server/src/external_pay_http.rs` 形态）。
/// - `do_response`：Go 的 `DoResponse` 直接向客户端写流并返回 usage。Rust 侧
///   客户端写出经 [`crate::adaptor_common::ClientSink`] 注入，返回
///   [`DoResponseOutcome`]（usage 与错误并存——Go 的 `(usage, *NewAPIError)`）。
/// - `convert_audio_request`：Go 接口有而此处原缺失（audio.go 特化路径）。
pub trait Adaptor {
    /// Go `Init(info)`。
    fn init(&mut self, info: &mut crate::relay_info::RelayInfo);
    /// Go `GetRequestURL(info)`。Go 会在此改写 info（UpstreamModelName 裁剪、
    /// ChannelBaseUrl ws 改写），因此携带 `&mut`。
    fn get_request_url(&self, info: &mut crate::relay_info::RelayInfo) -> Result<String, String>;
    /// Go `SetupRequestHeader(c, req, info)`：返回待写入的 header 键值。
    /// `client_headers` 是 `c.Header(...)` 的快照。
    fn setup_request_header(
        &self,
        info: &crate::relay_info::RelayInfo,
        client_headers: &[(String, String)],
    ) -> Result<Vec<(String, String)>, String>;
    /// Go `ConvertOpenAIRequest(...)`。
    fn convert_openai_request(
        &self,
        info: &mut crate::relay_info::RelayInfo,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, String>;
    /// Go `ConvertClaudeRequest(...)`。
    fn convert_claude_request(
        &self,
        info: &mut crate::relay_info::RelayInfo,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, String>;
    /// Go `ConvertGeminiRequest(...)`。
    fn convert_gemini_request(
        &self,
        info: &mut crate::relay_info::RelayInfo,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, String>;
    /// Go `ConvertRerankRequest(...)`。
    fn convert_rerank_request(
        &self,
        relay_mode: i32,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, String>;
    /// Go `ConvertEmbeddingRequest(...)`。
    fn convert_embedding_request(
        &self,
        info: &mut crate::relay_info::RelayInfo,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, String>;
    /// Go `ConvertImageRequest(...)`。
    fn convert_image_request(
        &self,
        info: &mut crate::relay_info::RelayInfo,
        request: &serde_json::Value,
        multipart: Option<&crate::adaptor_common::ParsedMultipartForm>,
    ) -> Result<crate::adaptor_common::ConvertedRequestBody, String>;
    /// Go `ConvertOpenAIResponsesRequest(...)`。
    fn convert_openai_responses_request(
        &self,
        info: &mut crate::relay_info::RelayInfo,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, String>;
    /// Go `ConvertAudioRequest(...)`：speech 分支返回 JSON 体积，其余分支返回
    /// multipart 体。
    fn convert_audio_request(
        &self,
        info: &mut crate::relay_info::RelayInfo,
        request: &serde_json::Value,
        multipart: Option<&crate::adaptor_common::ParsedMultipartForm>,
    ) -> Result<crate::adaptor_common::ConvertedRequestBody, String>;
    /// Go `DoRequest(a, c, info, requestBody)`：装配外呼请求并经 transport
    /// 执行。默认实现留给尚未移植的 45 个适配器（合并时逐个替换）。
    fn do_request<'a>(
        &'a self,
        info: &'a mut crate::relay_info::RelayInfo,
        context: &'a crate::adaptor_common::RequestContext<'_>,
        request_body: &'a [u8],
        transport: &'a dyn crate::adaptor_common::OutboundTransport,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        crate::adaptor_common::OutboundResponse,
                        crate::relay_info::AdaptorError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        let _ = (info, context, request_body, transport);
        Box::pin(async {
            Err(crate::relay_info::AdaptorError {
                status_code: 500,
                message: "adaptor outbound dispatch not ported yet".to_owned(),
                code: "bad_response".to_owned(),
                error_type: "new_api_error".to_owned(),
                skip_retry: false,
            })
        })
    }
    /// Go `DoResponse(c, resp, info)`：解析上游响应、折算 usage、经 sink 写出
    /// 客户端载荷。usage 与错误并存（Go `(usage any, err *NewAPIError)`）。
    fn do_response(
        &self,
        info: &mut crate::relay_info::RelayInfo,
        response: &mut crate::adaptor_common::OutboundResponse,
        sink: &mut dyn crate::adaptor_common::ClientSink,
    ) -> crate::adaptor_common::DoResponseOutcome;
    /// Go `GetModelList()`。
    fn get_model_list(&self) -> Vec<String>;
    /// Go `GetChannelName()`。
    fn get_channel_name(&self) -> String;
}

/// Go `GetTaskPlatform`（resolve_adaptor.go:139-146）的渠道侧输入。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskPlatform {
    /// `channel_type > 0`：平台 = 渠道类型十进制串。
    Channel(i32),
    /// 否则取上下文里的 `platform` 字符串。
    Named(String),
    /// 两者皆空（Go 返回空 TaskPlatform）。
    None,
}

/// Go `GetTaskAdaptor`（resolve_adaptor.go:151-183）的返回占位。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskAdaptorKind {
    Suno,
    Ali,
    Kling,
    Jimeng,
    Vertex,
    Vidu,
    Doubao,
    Sora,
    Gemini,
    Hailuo,
}

/// Go `GetAdaptor`（resolve_adaptor.go:40-121）。
pub fn resolve_adaptor(api_type: i32) -> Option<AdaptorKind> {
    Some(match api_type {
        api_type::ALI => AdaptorKind::Ali,
        api_type::ANTHROPIC => AdaptorKind::Anthropic,
        api_type::BAIDU => AdaptorKind::Baidu,
        api_type::GEMINI => AdaptorKind::Gemini,
        api_type::OPENAI => AdaptorKind::OpenAI,
        api_type::PALM => AdaptorKind::Palm,
        api_type::TENCENT => AdaptorKind::Tencent,
        api_type::XUNFEI => AdaptorKind::Xunfei,
        api_type::ZHIPU => AdaptorKind::Zhipu,
        api_type::ZHIPU_V4 => AdaptorKind::ZhipuV4,
        api_type::OLLAMA => AdaptorKind::Ollama,
        api_type::PERPLEXITY => AdaptorKind::Perplexity,
        api_type::AWS => AdaptorKind::Aws,
        api_type::COHERE => AdaptorKind::Cohere,
        api_type::DIFY => AdaptorKind::Dify,
        api_type::JINA => AdaptorKind::Jina,
        api_type::CLOUDFLARE => AdaptorKind::Cloudflare,
        api_type::SILICON_FLOW => AdaptorKind::SiliconFlow,
        api_type::VERTEX_AI => AdaptorKind::VertexAi,
        api_type::MISTRAL => AdaptorKind::Mistral,
        api_type::DEEP_SEEK => AdaptorKind::DeepSeek,
        api_type::MOKA_AI => AdaptorKind::MokaAi,
        api_type::VOLC_ENGINE => AdaptorKind::VolcEngine,
        api_type::BAIDU_V2 => AdaptorKind::BaiduV2,
        api_type::OPEN_ROUTER | api_type::XINFERENCE => AdaptorKind::OpenAiCompat,
        api_type::XAI => AdaptorKind::Xai,
        api_type::COZE => AdaptorKind::Coze,
        api_type::JIMENG => AdaptorKind::Jimeng,
        api_type::MOONSHOT => AdaptorKind::Moonshot,
        api_type::SUBMODEL => AdaptorKind::Submodel,
        api_type::MINI_MAX => AdaptorKind::MiniMax,
        api_type::REPLICATE => AdaptorKind::Replicate,
        api_type::CODEX => AdaptorKind::Codex,
        api_type::ADVANCED_CUSTOM => AdaptorKind::AdvancedCustom,
        api_type::SUB2API => AdaptorKind::Sub2Api,
        api_type::NEW_API => AdaptorKind::NewApi,
        _ => return None,
    })
}

/// Go `GetTaskAdaptor`（resolve_adaptor.go:151-183）。`TaskPlatformSuno` 名下
/// 返回 Suno；渠道类型整数平台按 ChannelType 分派。
pub fn resolve_task_adaptor(platform: &TaskPlatform) -> Option<TaskAdaptorKind> {
    use channel_type as ct;
    match platform {
        TaskPlatform::Named(name) if name == "suno" => Some(TaskAdaptorKind::Suno),
        TaskPlatform::Channel(channel_type) => match *channel_type {
            ct::ALI => Some(TaskAdaptorKind::Ali),
            ct::KLING => Some(TaskAdaptorKind::Kling),
            ct::JIMENG => Some(TaskAdaptorKind::Jimeng),
            ct::VERTEX_AI => Some(TaskAdaptorKind::Vertex),
            ct::VIDU => Some(TaskAdaptorKind::Vidu),
            ct::DOUBAO_VIDEO | ct::VOLC_ENGINE => Some(TaskAdaptorKind::Doubao),
            ct::SORA | ct::OPENAI => Some(TaskAdaptorKind::Sora),
            ct::GEMINI => Some(TaskAdaptorKind::Gemini),
            ct::MINI_MAX => Some(TaskAdaptorKind::Hailuo),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_type_mapping_round_trip() {
        let (api, ok) = channel_type_to_api_type(channel_type::ANTHROPIC);
        assert!(ok);
        assert_eq!(api, api_type::ANTHROPIC);
        // OpenRouter / Xinference 渠道映射到自己的 API 类型。
        assert_eq!(
            channel_type_to_api_type(channel_type::OPEN_ROUTER),
            (api_type::OPEN_ROUTER, true)
        );
        // 未映射渠道回退 OpenAI 且 ok=false。
        assert_eq!(
            channel_type_to_api_type(channel_type::AZURE),
            (api_type::OPENAI, false)
        );
        assert_eq!(
            channel_type_to_api_type(channel_type::UNKNOWN),
            (api_type::OPENAI, false)
        );
    }

    #[test]
    fn resolve_adaptor_registry() {
        assert_eq!(
            resolve_adaptor(api_type::ANTHROPIC),
            Some(AdaptorKind::Anthropic)
        );
        assert_eq!(
            resolve_adaptor(api_type::OPEN_ROUTER),
            Some(AdaptorKind::OpenAiCompat)
        );
        assert_eq!(
            resolve_adaptor(api_type::XINFERENCE),
            Some(AdaptorKind::OpenAiCompat)
        );
        assert_eq!(resolve_adaptor(api_type::DUMMY), None);
        assert_eq!(resolve_adaptor(-1), None);
    }

    #[test]
    fn task_adaptor_platform() {
        assert_eq!(
            resolve_task_adaptor(&TaskPlatform::Named("suno".to_owned())),
            Some(TaskAdaptorKind::Suno)
        );
        assert_eq!(
            resolve_task_adaptor(&TaskPlatform::Channel(channel_type::GEMINI)),
            Some(TaskAdaptorKind::Gemini)
        );
        assert_eq!(
            resolve_task_adaptor(&TaskPlatform::Channel(channel_type::DOUBAO_VIDEO)),
            Some(TaskAdaptorKind::Doubao)
        );
        assert_eq!(resolve_task_adaptor(&TaskPlatform::Channel(999)), None);
    }

    #[test]
    fn responses_compact_types() {
        assert!(is_responses_compact_api_type(api_type::CODEX));
        assert!(!is_responses_compact_api_type(api_type::ANTHROPIC));
    }
}
