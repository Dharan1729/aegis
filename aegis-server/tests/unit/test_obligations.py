from app.decision import Obligations


def test_empty_annotations_mean_no_obligations():
    o = Obligations.from_annotations({})
    assert o == Obligations(mask_fields=[], approval_required=False, risk_tier=None)


def test_fields_are_trimmed_and_blank_entries_dropped():
    o = Obligations.from_annotations({"mask_fields": " ssn, ,salary ,"})
    assert o.mask_fields == ["ssn", "salary"]


def test_approval_is_only_true_for_the_word_true():
    assert Obligations.from_annotations({"approval_required": " TRUE "}).approval_required
    assert not Obligations.from_annotations({"approval_required": "yes"}).approval_required
    assert not Obligations.from_annotations({"approval_required": "false"}).approval_required


def test_risk_tier_is_normalised():
    assert Obligations.from_annotations({"risk_tier": " Low "}).risk_tier == "low"
    assert Obligations.from_annotations({"risk_tier": ""}).risk_tier is None
