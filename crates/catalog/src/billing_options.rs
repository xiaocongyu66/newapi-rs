//! Deterministic, non-executing planning for legacy billing option migration.
//!
//! This module deliberately contains no database or transaction code. It turns
//! decoded rows into an inspectable plan; a caller may later execute that plan
//! under its own migration policy.

use std::collections::BTreeMap;

use serde::Serialize;

/// One row from the legacy ModelBillingMode/ModelBillingExpr options.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct LegacyBillingRecord {
    pub model: String,
    pub mode: Option<String>,
    pub expr: Option<String>,
}

/// The already-present value in the target billing_setting option.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct BillingSettingRecord {
    pub model: String,
    pub mode: Option<String>,
    pub expr: Option<String>,
}

/// A fixed, value-free classification of invalid input or an unusable plan.
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MergeError {
    EmptyModel,
    EmptyLegacyValue,
    InvalidTargetRecord,
    DuplicateTargetModel,
    DuplicateLegacyModel,
}

/// One planned decision. Values are retained in the plan for the eventual
/// executor, but this type intentionally does not implement `Debug`.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum PlanStep {
    KeepTarget(BillingSettingRecord),
    KeepLegacy(LegacyBillingRecord),
    DiscardEmptyLegacy { model: String },
}

/// Complete result of planning. No step has been applied to a database.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct MergePlan {
    pub steps: Vec<PlanStep>,
}

fn nonempty(value: &Option<String>) -> bool {
    value.as_deref().is_some_and(|value| !value.is_empty())
}

fn valid_model(model: &str) -> bool {
    !model.is_empty()
}

/// Build a deterministic merge plan for the legacy billing options.
///
/// Target records win over legacy records. Legacy records with no usable mode
/// or expression are discarded. Existing target records are never deleted, and
/// no transaction or write is performed here. Duplicate models are rejected so
/// a caller cannot accidentally obtain a plausible but order-dependent plan.
/// Inputs are validated completely before a plan is returned; an error never
/// returns a partial success.
pub fn plan_billing_options_merge(
    legacy: &[LegacyBillingRecord],
    target: &[BillingSettingRecord],
) -> Result<MergePlan, MergeError> {
    let mut target_by_model = BTreeMap::new();
    for record in target {
        if !valid_model(&record.model) || (!nonempty(&record.mode) && !nonempty(&record.expr)) {
            return Err(MergeError::InvalidTargetRecord);
        }
        if target_by_model
            .insert(record.model.clone(), record.clone())
            .is_some()
        {
            return Err(MergeError::DuplicateTargetModel);
        }
    }

    let mut legacy_by_model = BTreeMap::new();
    for record in legacy {
        if !valid_model(&record.model) {
            return Err(MergeError::EmptyModel);
        }
        if legacy_by_model
            .insert(record.model.clone(), record.clone())
            .is_some()
        {
            return Err(MergeError::DuplicateLegacyModel);
        }
    }

    let mut steps_by_model = BTreeMap::new();
    for (model, record) in target_by_model {
        steps_by_model.insert(model.clone(), PlanStep::KeepTarget(record));
        legacy_by_model.remove(&model);
    }
    for (model, record) in legacy_by_model {
        let step = if nonempty(&record.mode) || nonempty(&record.expr) {
            PlanStep::KeepLegacy(record)
        } else {
            PlanStep::DiscardEmptyLegacy {
                model: model.clone(),
            }
        };
        steps_by_model.insert(model, step);
    }

    Ok(MergePlan {
        steps: steps_by_model.into_values().collect(),
    })
}
