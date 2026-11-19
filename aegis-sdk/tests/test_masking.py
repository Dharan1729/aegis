import json

from aegis.masking import MASK, mask
from tests.conftest import EMPLOYEE


def test_no_fields_is_a_no_op():
    obj = object()
    r = mask(obj, [])
    assert r.ok and r.value is obj


def test_nested_keys_are_masked_case_insensitively():
    r = mask(EMPLOYEE, ["ssn"])
    assert r.ok and r.masked_keys == 2
    assert r.value["ssn"] == MASK and r.value["team"]["SSN"] == MASK
    assert r.value["name"] == "Ada" and r.value["team"]["lead"] == "Grace"
    assert EMPLOYEE["ssn"] == "123-45-6789"  # the input is not mutated


def test_lists_of_records():
    r = mask([EMPLOYEE, {"ssn": "x"}], ["ssn"])
    assert [row["ssn"] for row in r.value] == [MASK, MASK]


def test_json_strings_are_masked_and_stay_json():
    r = mask(json.dumps(EMPLOYEE), ["ssn"])
    assert r.ok and json.loads(r.value)["ssn"] == MASK


def test_pydantic_models_are_masked():
    from pydantic import BaseModel

    class Employee(BaseModel):
        name: str
        ssn: str

    r = mask(Employee(name="Ada", ssn="1"), ["ssn"])
    assert r.ok and r.value == {"name": "Ada", "ssn": MASK}


def test_free_text_cannot_be_masked():
    assert not mask("Ada's SSN is 123-45-6789", ["ssn"]).ok
    assert not mask('"123-45-6789"', ["ssn"]).ok  # a bare JSON string


def test_numbers_and_none_have_nothing_to_mask():
    assert mask(42, ["ssn"]).ok and mask(None, ["ssn"]).ok
