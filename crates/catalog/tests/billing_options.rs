use newapi_catalog::{
    plan_billing_options_merge, BillingSettingRecord, LegacyBillingRecord, MergeError, PlanStep,
};

fn legacy(model: &str, mode: Option<&str>, expr: Option<&str>) -> LegacyBillingRecord {
    LegacyBillingRecord {
        model: model.into(),
        mode: mode.map(str::to_owned),
        expr: expr.map(str::to_owned),
    }
}

fn target(model: &str, mode: Option<&str>, expr: Option<&str>) -> BillingSettingRecord {
    BillingSettingRecord {
        model: model.into(),
        mode: mode.map(str::to_owned),
        expr: expr.map(str::to_owned),
    }
}

#[test]
fn target_wins_and_legacy_rows_are_retained_or_discarded() {
    let plan = plan_billing_options_merge(
        &[
            legacy("same", Some("legacy"), Some("old")),
            legacy("keep", None, Some("x")),
            legacy("empty", None, None),
        ],
        &[target("same", Some("target"), Some("new"))],
    )
    .unwrap();

    assert_eq!(plan.steps.len(), 3);
    assert!(matches!(&plan.steps[0], PlanStep::DiscardEmptyLegacy { model } if model == "empty"));
    assert!(matches!(&plan.steps[1], PlanStep::KeepLegacy(record) if record.model == "keep"));
    assert!(matches!(&plan.steps[2], PlanStep::KeepTarget(record) if record.model == "same"));
}

#[test]
fn malformed_inputs_fail_without_partial_success() {
    assert!(matches!(
        plan_billing_options_merge(&[legacy("", Some("ratio"), None)], &[]),
        Err(MergeError::EmptyModel)
    ));
    assert!(matches!(
        plan_billing_options_merge(&[], &[target("bad", None, None)]),
        Err(MergeError::InvalidTargetRecord)
    ));
    assert!(matches!(
        plan_billing_options_merge(
            &[legacy("same", Some("a"), None), legacy("same", Some("b"), None)],
            &[]
        ),
        Err(MergeError::DuplicateLegacyModel)
    ));
    assert!(matches!(
        plan_billing_options_merge(
            &[],
            &[target("same", Some("a"), None), target("same", None, Some("b"))]
        ),
        Err(MergeError::DuplicateTargetModel)
    ));
}

#[test]
fn ordering_is_independent_of_input_order() {
    let first = plan_billing_options_merge(
        &[legacy("z", Some("z"), None), legacy("a", None, None)],
        &[target("m", Some("m"), None)],
    )
    .unwrap();
    let second = plan_billing_options_merge(
        &[legacy("a", None, None), legacy("z", Some("z"), None)],
        &[target("m", Some("m"), None)],
    )
    .unwrap();
    assert_eq!(first, second);
}
