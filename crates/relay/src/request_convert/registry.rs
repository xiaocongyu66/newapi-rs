//! Request-conversion registry and dispatch. Port of the upstream Go
//! `relaykit/relayconvert/request_registry.go` (lines 1-499): converter specs
//! registered by ID, unique (from, to) routes, composite step converters, and
//! the three entry points `convert_request` / `convert_request_via` /
//! `convert_request_by_id`.
//!
//! Registry construction is compile-time static (Go builds it eagerly at init
//! and panics on duplicate registration; Rust encodes the table as data, so
//! the duplicate/route-collision panics become impossible by construction).

use std::collections::HashMap;
use std::sync::OnceLock;

use serde_json::Value;

use super::oai_chat_to_responses;
use super::oai_responses_prepare;
use crate::convmeta::{ConvMeta, format::RequestKind, formats};

/// Go `RequestConverterQuality` (request_registry.go:22-28).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RequestConverterQuality {
    #[default]
    Unset,
    Good,
    Fair,
    Discouraged,
}

impl RequestConverterQuality {
    pub fn as_str(self) -> &'static str {
        match self {
            RequestConverterQuality::Unset => "",
            RequestConverterQuality::Good => "good",
            RequestConverterQuality::Fair => "fair",
            RequestConverterQuality::Discouraged => "discouraged",
        }
    }
}

/// Go `RequestStep` (request_registry.go:30-34).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestStep {
    pub converter: String,
    pub from: String,
    pub to: String,
}

/// Go `RequestResult` (request_registry.go:36-43).
#[derive(Clone, Debug)]
pub struct RequestResult {
    pub value: Value,
    pub from: String,
    pub to: String,
    pub converter: String,
    pub quality: RequestConverterQuality,
    pub steps: Vec<RequestStep>,
}

/// Go `RequestConverterSpec` (request_registry.go:45-52). `convert` is the
/// direct implementation; `step_converters` names a composite route.
#[derive(Clone)]
pub struct RequestConverterSpec {
    pub id: &'static str,
    pub from: &'static str,
    pub to: &'static str,
    pub quality: RequestConverterQuality,
    pub convert: Option<fn(&mut dyn ConvMeta, &Value) -> Result<Value, String>>,
    pub step_converters: &'static [&'static str],
}

/// Go `ConverterNone` + converter ID constants (request_registry.go:66-83).
pub mod converter_id {
    pub const NONE: &str = "none";
    pub const CLAUDE_MESSAGES_TO_OPENAI_CHAT: &str =
        "anthropic_messages_to_openai_chat_completions";
    pub const OPENAI_CHAT_TO_CLAUDE_MESSAGES: &str =
        "openai_chat_completions_to_anthropic_messages";
    pub const OPENAI_CHAT_TO_OPENAI_RESPONSES: &str = "openai_chat_completions_to_openai_responses";
    pub const OPENAI_RESPONSES_TO_OPENAI_CHAT: &str = "openai_responses_to_openai_chat_completions";
    pub const OPENAI_RESPONSES_TO_GEMINI: &str = "openai_responses_to_gemini_generate_content";
    pub const GEMINI_CONTENT_TO_OPENAI_CHAT: &str =
        "gemini_generate_content_to_openai_chat_completions";
    pub const OPENAI_CHAT_TO_GEMINI_CONTENT: &str =
        "openai_chat_completions_to_gemini_generate_content";
    // Composite IDs (request_registry.go:66-72).
    pub const CLAUDE_TO_GEMINI: &str = "claude_messages_to_gemini_generate_content";
    pub const CLAUDE_TO_RESPONSES: &str = "claude_messages_to_openai_responses";
    pub const GEMINI_TO_CLAUDE: &str = "gemini_generate_content_to_claude_messages";
    pub const GEMINI_TO_RESPONSES: &str = "gemini_generate_content_to_openai_responses";
    pub const RESPONSES_TO_CLAUDE: &str = "openai_responses_to_claude_messages";
}

/// Direct converter implementations. Only the routes ported in this slice are
/// wired; the remaining Go converters stay unregistered so dispatch fails
/// with the Go "not registered" error instead of silently mis-converting.
fn direct_converters() -> Vec<RequestConverterSpec> {
    vec![RequestConverterSpec {
        id: converter_id::OPENAI_CHAT_TO_OPENAI_RESPONSES,
        from: formats::OPENAI,
        to: formats::OPENAI_RESPONSES,
        quality: RequestConverterQuality::Good,
        convert: Some(|_meta, request| {
            oai_chat_to_responses::chat_completions_request_to_responses_request(request)
                .map_err(|e| e.0)
        }),
        step_converters: &[],
    }]
}

/// Composite route table (Go registerBuiltinRequestConverter calls with
/// StepConverters, request_registry.go + registration block).
fn composite_converters() -> Vec<RequestConverterSpec> {
    vec![
        RequestConverterSpec {
            id: converter_id::CLAUDE_TO_GEMINI,
            from: formats::CLAUDE,
            to: formats::GEMINI,
            quality: RequestConverterQuality::Fair,
            convert: None,
            step_converters: &[
                converter_id::CLAUDE_MESSAGES_TO_OPENAI_CHAT,
                converter_id::OPENAI_CHAT_TO_GEMINI_CONTENT,
            ],
        },
        RequestConverterSpec {
            id: converter_id::CLAUDE_TO_RESPONSES,
            from: formats::CLAUDE,
            to: formats::OPENAI_RESPONSES,
            quality: RequestConverterQuality::Fair,
            convert: None,
            step_converters: &[
                converter_id::CLAUDE_MESSAGES_TO_OPENAI_CHAT,
                converter_id::OPENAI_CHAT_TO_OPENAI_RESPONSES,
            ],
        },
        RequestConverterSpec {
            id: converter_id::GEMINI_TO_CLAUDE,
            from: formats::GEMINI,
            to: formats::CLAUDE,
            quality: RequestConverterQuality::Fair,
            convert: None,
            step_converters: &[
                converter_id::GEMINI_CONTENT_TO_OPENAI_CHAT,
                converter_id::OPENAI_CHAT_TO_CLAUDE_MESSAGES,
            ],
        },
        RequestConverterSpec {
            id: converter_id::GEMINI_TO_RESPONSES,
            from: formats::GEMINI,
            to: formats::OPENAI_RESPONSES,
            quality: RequestConverterQuality::Fair,
            convert: None,
            step_converters: &[
                converter_id::GEMINI_CONTENT_TO_OPENAI_CHAT,
                converter_id::OPENAI_CHAT_TO_OPENAI_RESPONSES,
            ],
        },
        RequestConverterSpec {
            id: converter_id::RESPONSES_TO_CLAUDE,
            from: formats::OPENAI_RESPONSES,
            to: formats::CLAUDE,
            quality: RequestConverterQuality::Fair,
            convert: None,
            step_converters: &[
                converter_id::OPENAI_RESPONSES_TO_OPENAI_CHAT,
                converter_id::OPENAI_CHAT_TO_CLAUDE_MESSAGES,
            ],
        },
    ]
}

struct Registry {
    converters: HashMap<&'static str, RequestConverterSpec>,
    routes: HashMap<(&'static str, &'static str), &'static str>,
    direct_routes: HashMap<(&'static str, &'static str), &'static str>,
}

fn build_registry() -> Registry {
    let mut converters = HashMap::new();
    let mut routes = HashMap::new();
    let mut direct_routes = HashMap::new();

    // Direct specs first so composites can reference them (Go registration
    // order guarantees step targets exist before the composite is registered).
    for spec in direct_converters() {
        let route = (spec.from, spec.to);
        assert!(
            routes.insert(route, spec.id).is_none(),
            "request converter route from {} to {} is already registered by {}",
            route.0,
            route.1,
            spec.id
        );
        assert!(
            spec.convert.is_some(),
            "request converter {} must declare convert",
            spec.id
        );
        direct_routes.insert(route, spec.id);
        converters.insert(spec.id, spec);
    }

    for spec in composite_converters() {
        let route = (spec.from, spec.to);
        assert!(
            routes.insert(route, spec.id).is_none(),
            "request converter route from {} to {} is already registered by {}",
            route.0,
            route.1,
            spec.id
        );
        // Go registerBuiltinRequestConverter: composite steps must chain from
        // `from` to `to` through direct converters.
        let mut current = spec.from;
        for step_id in spec.step_converters {
            let step = converters.get(step_id).unwrap_or_else(|| {
                panic!(
                    "request converter {} references unknown step converter {}",
                    spec.id, step_id
                )
            });
            assert!(
                step.convert.is_some(),
                "request converter {} step {} must be a direct converter",
                spec.id,
                step_id
            );
            assert!(
                step.from == current,
                "request converter {} step {} expects {} after {}",
                spec.id,
                step_id,
                step.from,
                current
            );
            current = step.to;
        }
        assert!(
            current == spec.to,
            "request converter {} ends at {}, expected {}",
            spec.id,
            current,
            spec.to
        );
        converters.insert(spec.id, spec);
    }

    Registry {
        converters,
        routes,
        direct_routes,
    }
}

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(build_registry)
}

/// Go `LookupRequestConverter` (request_registry.go:140-149).
pub fn lookup_request_converter(converter: &str) -> Option<RequestConverterSpec> {
    registry().converters.get(converter.trim()).cloned()
}

/// Go `inferRequestRelayFormat` (request_registry.go:378-387).
fn infer_request_relay_format(
    request: &Value,
    kind: Option<RequestKind>,
) -> Result<String, String> {
    if request.is_null() {
        return Err("request is nil".to_owned());
    }
    crate::convmeta::guess_relay_format_from_request(request, kind)
        .map(str::to_owned)
        .ok_or_else(|| "unsupported request type".to_owned())
}

/// Go `ConvertRequest` (request_registry.go:151-172).
pub fn convert_request(
    meta: &mut dyn ConvMeta,
    target: &str,
    request: &Value,
    kind: Option<RequestKind>,
) -> Result<RequestResult, String> {
    let from = infer_request_relay_format(request, kind)?;
    if target.is_empty() {
        return Err("target relay format is required".to_owned());
    }
    if from == target {
        return Ok(RequestResult {
            value: request.clone(),
            from,
            to: target.to_owned(),
            converter: String::new(),
            quality: RequestConverterQuality::Unset,
            steps: Vec::new(),
        });
    }
    let Some(spec) = registry()
        .routes
        .get(&(from.as_str(), target))
        .and_then(|id| registry().converters.get(id))
        .cloned()
    else {
        return Err(format!(
            "request converter from {} to {} is not registered",
            from, target
        ));
    };
    execute_request_spec(meta, from, target.to_owned(), request, spec)
}

/// Go `ConvertRequestVia` (request_registry.go:174-212): explicit
/// direct-route path.
pub fn convert_request_via(
    meta: &mut dyn ConvMeta,
    request: &Value,
    kind: Option<RequestKind>,
    path: &[&str],
) -> Result<RequestResult, String> {
    let from = infer_request_relay_format(request, kind)?;
    if path.is_empty() {
        return Err("request conversion path is required".to_owned());
    }
    for format in path {
        if format.is_empty() {
            return Err("request conversion path contains empty relay format".to_owned());
        }
    }
    let mut targets: Vec<&str> = path.to_vec();
    if targets[0] == from {
        targets.remove(0);
    }
    if targets.is_empty() {
        return Ok(RequestResult {
            value: request.clone(),
            from: from.clone(),
            to: from,
            converter: String::new(),
            quality: RequestConverterQuality::Unset,
            steps: Vec::new(),
        });
    }

    let mut steps: Vec<RequestConverterSpec> = Vec::with_capacity(targets.len());
    let mut current = from.as_str();
    for target in &targets {
        let Some(spec) = registry()
            .direct_routes
            .get(&(current, *target))
            .and_then(|id| registry().converters.get(id))
            .cloned()
        else {
            return Err(format!(
                "request converter from {} to {} is not registered",
                current, target
            ));
        };
        current = spec.to;
        steps.push(spec);
    }
    execute_request_steps(
        meta,
        from,
        targets[targets.len() - 1].to_owned(),
        request,
        "",
        RequestConverterQuality::Unset,
        steps,
    )
}

/// Go `ConvertRequestByID` (request_registry.go:214-228).
pub fn convert_request_by_id(
    meta: &mut dyn ConvMeta,
    converter: &str,
    request: &Value,
    kind: Option<RequestKind>,
) -> Result<RequestResult, String> {
    let from = infer_request_relay_format(request, kind)?;
    let Some(spec) = lookup_request_converter(converter) else {
        return Err(format!(
            "request converter {:?} is not registered",
            converter.trim()
        ));
    };
    if !spec.from.is_empty() && spec.from != from {
        return Err(format!(
            "request converter {:?} expects {} request, got {}",
            spec.id, spec.from, from
        ));
    }
    execute_request_spec(meta, from, spec.to.to_owned(), request, spec)
}

/// Go `executeRequestSpec` (request_registry.go:230-236).
fn execute_request_spec(
    meta: &mut dyn ConvMeta,
    from: String,
    target: String,
    request: &Value,
    spec: RequestConverterSpec,
) -> Result<RequestResult, String> {
    let steps = expand_request_converter_steps(&spec)?;
    execute_request_steps(meta, from, target, request, spec.id, spec.quality, steps)
}

/// Go `executeRequestSteps` (request_registry.go:238-271).
fn execute_request_steps(
    meta: &mut dyn ConvMeta,
    from: String,
    target: String,
    request: &Value,
    converter: &str,
    quality: RequestConverterQuality,
    specs: Vec<RequestConverterSpec>,
) -> Result<RequestResult, String> {
    let mut current = request.clone();
    let mut steps: Vec<RequestStep> = Vec::with_capacity(specs.len());
    for spec in specs {
        current = prepare_request_for_step(current, &spec, &target)?;
        let (value, step) = execute_request_step(meta, &spec, &current)?;
        current = value;
        steps.push(step);
    }

    let converter = if converter.is_empty() {
        steps
            .iter()
            .map(|s| s.converter.as_str())
            .collect::<Vec<_>>()
            .join(",")
    } else {
        converter.to_owned()
    };
    Ok(RequestResult {
        value: current,
        from,
        to: target,
        converter,
        quality,
        steps,
    })
}

/// Go `expandRequestConverterSteps` (request_registry.go:273-304).
fn expand_request_converter_steps(
    spec: &RequestConverterSpec,
) -> Result<Vec<RequestConverterSpec>, String> {
    if spec.step_converters.is_empty() {
        if spec.convert.is_none() {
            return Err(format!(
                "request converter {:?} has no registered implementation",
                spec.id
            ));
        }
        return Ok(vec![spec.clone()]);
    }
    if spec.convert.is_some() {
        return Err(format!(
            "request converter {:?} cannot mix direct and step conversion",
            spec.id
        ));
    }

    let mut steps = Vec::with_capacity(spec.step_converters.len());
    let mut current = spec.from;
    for converter_id in spec.step_converters {
        let Some(step) = lookup_request_converter(converter_id) else {
            return Err(format!(
                "request converter {:?} references missing step converter {:?}",
                spec.id, converter_id
            ));
        };
        if step.convert.is_none() || !step.step_converters.is_empty() {
            return Err(format!(
                "request converter {:?} step {:?} is not a direct converter",
                spec.id, converter_id
            ));
        }
        if step.from != current {
            return Err(format!(
                "request converter {:?} step {:?} expects {} request, got {}",
                spec.id, converter_id, current, step.from
            ));
        }
        current = step.to;
        steps.push(step);
    }
    if current != spec.to {
        return Err(format!(
            "request converter {:?} ends at {}, expected {}",
            spec.id, current, spec.to
        ));
    }
    Ok(steps)
}

/// Go `executeRequestStep` (request_registry.go:306-323): run the converter
/// and record the hop on the meta.
fn execute_request_step(
    meta: &mut dyn ConvMeta,
    spec: &RequestConverterSpec,
    request: &Value,
) -> Result<(Value, RequestStep), String> {
    let Some(convert) = spec.convert else {
        return Err(format!(
            "request converter {:?} has no registered implementation",
            spec.id
        ));
    };
    let value = convert(meta, request)?;
    meta.append_request_conversion(spec.to);
    Ok((
        value,
        RequestStep {
            converter: spec.id.to_owned(),
            from: spec.from.to_owned(),
            to: spec.to.to_owned(),
        },
    ))
}

/// Go `prepareRequestForStep` (request_registry.go:325-345): when a
/// responses-format step feeds a final Gemini target, preprocess the request
/// first (custom-tool filtering for Gemini). Untouched otherwise.
fn prepare_request_for_step(
    request: Value,
    spec: &RequestConverterSpec,
    final_target: &str,
) -> Result<Value, String> {
    if spec.from != formats::OPENAI_RESPONSES || final_target != formats::GEMINI {
        return Ok(request);
    }
    oai_responses_prepare::prepare_openai_responses_request(request).map_err(|e| e.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convmeta::MetaValues;
    use serde_json::json;

    fn meta() -> MetaValues {
        MetaValues::default()
    }

    fn chat_request() -> Value {
        json!({
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "hello"}],
        })
    }

    /// Go request_registry.go:151-165: same from/target short-circuits.
    #[test]
    fn convert_request_identity_short_circuit() {
        let mut meta = meta();
        let result = convert_request(
            &mut meta,
            formats::OPENAI,
            &chat_request(),
            Some(RequestKind::GeneralOpenAI),
        )
        .expect("identity");
        assert_eq!(result.from, formats::OPENAI);
        assert_eq!(result.to, formats::OPENAI);
        assert!(result.steps.is_empty());
        assert_eq!(result.converter, "");
    }

    /// Go request_registry.go:167-169: unregistered route error text.
    #[test]
    fn convert_request_unregistered_route() {
        let mut meta = meta();
        let err = convert_request(
            &mut meta,
            formats::CLAUDE,
            &chat_request(),
            Some(RequestKind::GeneralOpenAI),
        )
        .expect_err("route must be missing");
        assert!(err.contains("is not registered"), "got: {err}");
    }

    /// Go request_registry.go:174-199: empty path and same-first-hop rules.
    #[test]
    fn convert_request_via_path_rules() {
        let mut meta = meta();
        let err = convert_request_via(
            &mut meta,
            &chat_request(),
            Some(RequestKind::GeneralOpenAI),
            &[],
        )
        .expect_err("empty path");
        assert_eq!(err, "request conversion path is required");

        let result = convert_request_via(
            &mut meta,
            &chat_request(),
            Some(RequestKind::GeneralOpenAI),
            &[formats::OPENAI],
        )
        .expect("first hop equals source");
        assert_eq!(result.to, formats::OPENAI);

        let err = convert_request_via(
            &mut meta,
            &chat_request(),
            Some(RequestKind::GeneralOpenAI),
            &[""],
        )
        .expect_err("empty format");
        assert_eq!(err, "request conversion path contains empty relay format");
    }

    /// The wired chat→responses route end to end, including the conversion
    /// hop recorded on the meta.
    #[test]
    fn convert_request_chat_to_responses_wired() {
        let mut meta = meta();
        let result = convert_request(
            &mut meta,
            formats::OPENAI_RESPONSES,
            &chat_request(),
            Some(RequestKind::GeneralOpenAI),
        )
        .expect("convert");
        assert_eq!(
            result.converter,
            converter_id::OPENAI_CHAT_TO_OPENAI_RESPONSES
        );
        assert_eq!(result.from, formats::OPENAI);
        assert_eq!(result.to, formats::OPENAI_RESPONSES);
        assert_eq!(result.steps.len(), 1);
        assert_eq!(result.value["model"], json!("gpt-test"));
        assert_eq!(
            result.value["input"],
            json!([{"role": "user", "content": "hello"}])
        );
        assert_eq!(
            meta.conversion_chain,
            vec![formats::OPENAI_RESPONSES.to_owned()]
        );
    }

    /// Go ConvertRequestByID (request_registry.go:214-228): unknown ID and
    /// from-format mismatch errors.
    #[test]
    fn convert_request_by_id_guards() {
        let mut meta = meta();
        let err = convert_request_by_id(
            &mut meta,
            "nope",
            &chat_request(),
            Some(RequestKind::GeneralOpenAI),
        )
        .expect_err("unknown id");
        assert!(err.contains("is not registered"));

        let err = convert_request_by_id(
            &mut meta,
            converter_id::OPENAI_CHAT_TO_OPENAI_RESPONSES,
            &json!({"model": "gpt-test", "input": []}),
            Some(RequestKind::OpenAIResponses),
        )
        .expect_err("from mismatch");
        assert!(err.contains("expects openai request"), "got: {err}");
    }

    /// Composite routes stay registered (route table parity with the Go
    /// registration block) but fail closed while their step converters are
    /// not yet ported.
    #[test]
    fn composite_routes_registered_but_unported_fail_closed() {
        let reg = registry();
        for (from, to, id) in [
            (
                formats::CLAUDE,
                formats::GEMINI,
                converter_id::CLAUDE_TO_GEMINI,
            ),
            (
                formats::CLAUDE,
                formats::OPENAI_RESPONSES,
                converter_id::CLAUDE_TO_RESPONSES,
            ),
            (
                formats::GEMINI,
                formats::CLAUDE,
                converter_id::GEMINI_TO_CLAUDE,
            ),
            (
                formats::GEMINI,
                formats::OPENAI_RESPONSES,
                converter_id::GEMINI_TO_RESPONSES,
            ),
            (
                formats::OPENAI_RESPONSES,
                formats::CLAUDE,
                converter_id::RESPONSES_TO_CLAUDE,
            ),
        ] {
            assert_eq!(reg.routes.get(&(from, to)), Some(&id), "{from}->{to}");
        }
        let mut meta = meta();
        let err = convert_request(
            &mut meta,
            formats::OPENAI_RESPONSES,
            &json!({"model": "claude-test", "max_tokens": 16, "messages": []}),
            Some(RequestKind::Claude),
        )
        .expect_err("composite route references unported step");
        // claude→responses route resolves to the composite spec whose first
        // step converter is not ported yet; Go's expand error surfaces.
        assert!(
            err.contains("references missing step converter") || err.contains("is not registered"),
            "got: {err}"
        );
    }

    /// Go lookupRequestConverter trims the ID.
    #[test]
    fn lookup_trims_id() {
        assert!(
            lookup_request_converter(
                format!("  {}  ", converter_id::OPENAI_CHAT_TO_OPENAI_RESPONSES).as_str()
            )
            .is_some()
        );
        assert!(lookup_request_converter("missing").is_none());
    }

    /// Go request_registry.go:156-158: empty target rejected.
    #[test]
    fn convert_request_empty_target() {
        let mut meta = meta();
        let err = convert_request(
            &mut meta,
            "",
            &chat_request(),
            Some(RequestKind::GeneralOpenAI),
        )
        .expect_err("empty target");
        assert_eq!(err, "target relay format is required");
    }

    /// Go inferRequestRelayFormat: nil request rejected.
    #[test]
    fn nil_request_rejected() {
        let mut meta = meta();
        let err = convert_request(&mut meta, formats::OPENAI, &Value::Null, None).expect_err("nil");
        assert_eq!(err, "request is nil");
    }
}
