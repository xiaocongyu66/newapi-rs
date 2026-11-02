use std::collections::HashSet;

use newapi_security::{OriginRequest, check_session_origin};
use serde_json::Value;

fn field<'a>(object: &'a Value, key: &str) -> &'a Value {
    object.get(key).expect("预言机记录缺少必需字段")
}

fn boolean(object: &Value, key: &str) -> bool {
    field(object, key)
        .as_bool()
        .expect("预言机字段必须是布尔值")
}

fn text<'a>(object: &'a Value, key: &str) -> &'a str {
    field(object, key)
        .as_str()
        .expect("预言机字段必须是字符串")
}

fn headers<'a>(object: &'a Value, key: &str) -> Vec<&'a str> {
    let value = field(object, key);
    // 上游未设置的切片编码为 null，而不是空数组；不允许缺失字段。
    if value.is_null() {
        return Vec::new();
    }
    value
        .as_array()
        .expect("预言机头字段必须是数组或 null")
        .iter()
        .map(|entry| entry.as_str().expect("预言机头值必须是字符串"))
        .collect()
}

/// 必须由 Actions 提供真实上游导出，禁止缺失时跳过或改用本地预期。
/// 文件格式为每行一个模板实际输出的 JSON 对象，不含日志前缀。
#[test]
fn origin_matches_go_oracle() {
    let path = std::env::var_os("P2_ORIGIN_ORACLE_PATH")
        .filter(|value| !value.is_empty())
        .expect("CI 必须提供 P2_ORIGIN_ORACLE_PATH，禁止跳过来源差分测试");
    let contents = std::fs::read_to_string(path).expect("无法读取来源预言机夹具");
    let mut names = HashSet::new();
    let mut mismatches = Vec::new();
    let mut allowed_count = 0;
    let mut denied_count = 0;
    for (index, line) in contents.lines().enumerate() {
        assert!(!line.trim().is_empty(), "预言机夹具包含空行");
        // 不打印解析错误的原文，避免将意外混入的日志或凭据带入失败报告。
        let record: Value = serde_json::from_str(line).expect("预言机行不是有效 JSON 对象");
        let input = field(&record, "input");
        let name = text(input, "name");
        assert!(!name.is_empty(), "预言机用例名称为空");
        assert!(names.insert(name.to_owned()), "预言机用例名称重复");
        let host = text(input, "host");
        assert!(!host.is_empty(), "上游导出的主机不应为空");
        let origins = headers(input, "origins");
        let referers = headers(input, "referers");
        let trusted = headers(input, "trusted");
        let hosts = [host];
        let insecure = boolean(input, "insecure");
        let request = OriginRequest {
            secure_cookie: !insecure,
            transport_tls: !boolean(input, "plaintext"),
            host_headers: &hosts,
            origin_headers: &origins,
            referer_headers: &referers,
            trusted_urls: &trusted,
        };
        let expected = boolean(&record, "allowed");
        // 校验模板输出形状及其自身断言，判定基准仍是外层真实 Go 结果。
        assert_eq!(
            expected,
            boolean(input, "allowed"),
            "Go 实际判定与模板冻结预期不符，记录序号 {}",
            index + 1
        );
        let valid = boolean(&record, "valid");
        let _browser_origin = text(&record, "browser_origin");
        assert!(
            insecure || !expected || valid,
            "安全模式的 Go 允许结果必须具有合法来源"
        );
        if expected {
            allowed_count += 1;
        } else {
            denied_count += 1;
        }
        let actual = check_session_origin(&request).is_ok();
        if actual != expected {
            // 只报告序号与布尔判定；原始请求值不进入日志。
            mismatches.push((index + 1, expected, actual));
        }
    }
    // 当前模板包含四十项；禁止空文件或截断导出制造假绿，允许后续增加用例。
    assert!(names.len() >= 40, "预言机夹具不足四十项，可能导出不完整");
    for required in [
        "邮箱查询",
        "忽略重复来源页",
        "点段",
        "转义点",
        "IPv6不压缩",
        "IPv4缩写不等价",
        "国际域名不转码",
        "端口前导零不等价",
        "不信转发协议",
        "非安全配置",
    ] {
        assert!(names.contains(required), "预言机缺少必需回归用例");
    }
    assert!(allowed_count > 0 && denied_count > 0, "预言机必须覆盖允许与拒绝");
    assert!(
        mismatches.is_empty(),
        "Go/Rust 来源判定不一致（序号、Go、Rust）：{mismatches:?}"
    );
}
