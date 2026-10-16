from app_triage.models import ActionSpec, Finding, Risk, make_finding_id


def test_finding_id_stable_and_case_insensitive():
    assert make_finding_id("file_assoc", ".JPG") == make_finding_id("file_assoc", ".jpg")
    assert len(make_finding_id("a", "b")) == 12


def test_action_spec_param_lookup():
    s = ActionSpec("delete_reg_value", r"HKCU\X", (("name", "WPS"),))
    assert s.param("name") == "WPS" and s.param("missing", "d") == "d"


def test_finding_to_dict_serializes_risk_and_actions():
    f = Finding("id1", "autoruns", "t", {"k": "v"}, Risk.HIGH, [ActionSpec("k", "t")])
    d = f.to_dict()
    assert d["risk"] == "high" and d["actions"][0]["kind"] == "k"
