//! COSE 公钥与原始 CBOR 字节的互转。
//!
//! Go 侧把 `webauthn.Credential.PublicKey`（原始 CBOR 字节）base64 后存入
//! `public_key` 列；本模块用同样的字节格式落库，保证 Go 注册的凭据可被 Rust
//! 读回重建。webauthn-rs 只提供 `TryFrom<&serde_cbor_2::Value> for COSEKey`
//! 的单向解析，反向编码按 RFC 8152 的 COSE Key Map 手写，仅覆盖该库
//! `secure_algs()` 与实际认证器会出现的 EC2/OKP/RSA 三类键型。

use serde_cbor_2::Value;
use webauthn_rs::prelude::{COSEAlgorithm, COSEKey, COSEKeyType, ECDSACurve, EDDSACurve};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoseError {
    /// 不支持的键型或算法（无法编码为 COSE Key Map）。
    Unsupported,
    /// CBOR 结构不是合法的 COSE Key Map（解码失败时复用该分类）。
    Invalid,
}

impl std::fmt::Display for CoseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "unsupported COSE key type",
            Self::Invalid => "invalid COSE key encoding",
        })
    }
}

impl std::error::Error for CoseError {}

/// CBOR map 的整数键（RFC 8152 §3.1）。
const KTY: i128 = 1;
const ALG: i128 = 3;
const CRV: i128 = -1;
const X: i128 = -2;
const Y: i128 = -3;
/// COSE Key Type 标识。
const KTY_EC2: i128 = 2;
const KTY_OKP: i128 = 1;
const KTY_RSA: i128 = 3;

fn cbor_map(pairs: Vec<(i128, Value)>) -> Value {
    let mut map = std::collections::BTreeMap::new();
    for (key, value) in pairs {
        map.insert(Value::Integer(key), value);
    }
    Value::Map(map)
}

fn alg_value(alg: &COSEAlgorithm) -> Option<i128> {
    // `COSEAlgorithm` 是 `#[repr(i32)]` 的字段less枚举，判别式即 IANA 值。
    let value = match alg {
        COSEAlgorithm::ES256 => -7,
        COSEAlgorithm::ES384 => -35,
        COSEAlgorithm::ES521 => -36,
        COSEAlgorithm::EDDSA => -8,
        COSEAlgorithm::RS256 => -257,
        COSEAlgorithm::RS384 => -258,
        COSEAlgorithm::RS512 => -259,
        COSEAlgorithm::PS256 => -37,
        COSEAlgorithm::PS384 => -38,
        COSEAlgorithm::PS512 => -39,
        COSEAlgorithm::INSECURE_RS1 => -65_535,
        COSEAlgorithm::PinUvProtocol => return None,
    };
    Some(value as i128)
}

fn ecdsa_curve_value(curve: &ECDSACurve) -> Option<i128> {
    match curve {
        ECDSACurve::SECP256R1 => Some(1),
        ECDSACurve::SECP384R1 => Some(2),
        ECDSACurve::SECP521R1 => Some(3),
    }
}

fn eddsa_curve_value(curve: &EDDSACurve) -> Option<i128> {
    match curve {
        EDDSACurve::ED25519 => Some(6),
        EDDSACurve::ED448 => Some(7),
    }
}

/// COSEKey → 原始 CBOR 字节。键型/算法不在已知集合内时返回
/// `Unsupported`（不伪造未知结构）。
pub fn encode_cose_key(key: &COSEKey) -> Result<Vec<u8>, CoseError> {
    let alg = alg_value(&key.type_).ok_or(CoseError::Unsupported)?;
    let map = match &key.key {
        COSEKeyType::EC_EC2(ec) => {
            let crv = ecdsa_curve_value(&ec.curve).ok_or(CoseError::Unsupported)?;
            cbor_map(vec![
                (KTY, Value::Integer(KTY_EC2)),
                (ALG, Value::Integer(alg)),
                (CRV, Value::Integer(crv)),
                (X, Value::Bytes(ec.x.clone())),
                (Y, Value::Bytes(ec.y.clone())),
            ])
        }
        COSEKeyType::EC_OKP(okp) => {
            let crv = eddsa_curve_value(&okp.curve).ok_or(CoseError::Unsupported)?;
            cbor_map(vec![
                (KTY, Value::Integer(KTY_OKP)),
                (ALG, Value::Integer(alg)),
                (CRV, Value::Integer(crv)),
                (X, Value::Bytes(okp.x.clone())),
            ])
        }
        COSEKeyType::RSA(rsa) => cbor_map(vec![
            (KTY, Value::Integer(KTY_RSA)),
            (ALG, Value::Integer(alg)),
            (X, Value::Bytes(rsa.n.clone())),
            (Y, Value::Bytes(rsa.e.to_vec())),
        ]),
    };
    serde_cbor_2::to_vec(&map).map_err(|_| CoseError::Invalid)
}

/// 原始 CBOR 字节 → COSEKey，先按 `serde_cbor_2` 解到 Value，再走
/// webauthn-rs 的 `TryFrom<&Value>`（与认证器数据解析同一条路径）。
pub fn decode_cose_key(bytes: &[u8]) -> Result<COSEKey, CoseError> {
    let value = serde_cbor_2::from_slice::<Value>(bytes).map_err(|_| CoseError::Invalid)?;
    COSEKey::try_from(&value).map_err(|_| CoseError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use webauthn_rs::prelude::COSEEC2Key;

    /// P-256 生成元点 G 的坐标。`COSEKey::try_from` 以 `validate()` 校验坐标
    /// 必须落在曲线上（`EcdsaPointInvalid`），测试键不能是任意字节。
    const G_X: [u8; 32] = [
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96,
    ];
    const G_Y: [u8; 32] = [
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
        0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf,
        0x51, 0xf5,
    ];

    fn ec2_key() -> COSEKey {
        COSEKey {
            type_: COSEAlgorithm::ES256,
            key: COSEKeyType::EC_EC2(COSEEC2Key {
                curve: ECDSACurve::SECP256R1,
                x: G_X.to_vec(),
                y: G_Y.to_vec(),
            }),
        }
    }

    #[test]
    fn roundtrip_es256() {
        let key = ec2_key();
        let bytes = encode_cose_key(&key).expect("encode");
        let back = decode_cose_key(&bytes).expect("decode");
        assert_eq!(back, key);
    }

    #[test]
    fn encoding_matches_the_cose_key_map_shape() {
        let bytes = encode_cose_key(&ec2_key()).expect("encode");
        let value = serde_cbor_2::from_slice::<Value>(&bytes).expect("cbor");
        let map = match value {
            Value::Map(map) => map,
            _ => panic!("expected a CBOR map"),
        };
        let get = |key: i128| map.get(&Value::Integer(key));
        assert_eq!(get(KTY), Some(&Value::Integer(KTY_EC2)));
        assert_eq!(get(ALG), Some(&Value::Integer(-7)));
        assert_eq!(get(CRV), Some(&Value::Integer(1)));
        assert_eq!(get(X), Some(&Value::Bytes(G_X.to_vec())));
        assert_eq!(get(Y), Some(&Value::Bytes(G_Y.to_vec())));
    }

    #[test]
    fn invalid_bytes_are_rejected() {
        assert!(decode_cose_key(&[0x00]).is_err());
        // 合法 CBOR 但不是 COSE Key Map。
        assert!(decode_cose_key(b"[]").is_err());
    }
}
