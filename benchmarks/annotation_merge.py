"""Two policies allow the same request and both set `mask_fields`.

Sends the identical /authorize request to a cedar-sidecar many times and
counts how often each field that some policy asked to mask is missing from
the response. Used to compare the merge before and after 0.2.0 (the old
sidecar merged annotations into a HashMap, last write wins).

    python -m benchmarks.annotation_merge --url http://localhost:8180 --label after
"""

import argparse
import collections
import json

import httpx

from benchmarks._stack import write_result

POLICIES = """
@mask_fields("ssn")
permit(principal, action == Action::"read_employee", resource) when { principal.role == "Analyst" };

@mask_fields("salary")
permit(principal, action == Action::"read_employee", resource) when { principal.department == "Finance" };
"""

REQUEST = {
    "policy_set": POLICIES,
    "entities": [
        {
            "uid": {"type": "Human", "id": "alice"},
            "attrs": {"role": "Analyst", "department": "Finance"},
            "parents": [],
        },
        {"uid": {"type": "Resource", "id": "urn:e"}, "attrs": {"type": "employee"}, "parents": []},
    ],
    "principal": 'Human::"alice"',
    "action": 'Action::"read_employee"',
    "resource": 'Resource::"urn:e"',
    "context": {},
}


def run(url: str, n: int) -> dict:
    outcomes = collections.Counter()
    with httpx.Client(timeout=5.0) as client:
        for _ in range(n):
            body = client.post(f"{url}/authorize", json=REQUEST).json()
            fields = sorted(
                f.strip() for f in body["annotations"].get("mask_fields", "").split(",") if f.strip()
            )
            outcomes[",".join(fields) or "<none>"] += 1
    complete = outcomes.get("salary,ssn", 0)
    return {
        "requests": n,
        "outcomes": dict(outcomes),
        "both_fields_masked": complete,
        "a_field_left_unmasked": n - complete,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:8180")
    parser.add_argument("--label", required=True)
    parser.add_argument("--requests", type=int, default=500)
    args = parser.parse_args()
    result = run(args.url, args.requests)
    print(json.dumps(result, indent=2))
    print("wrote", write_result(f"annotation_merge_{args.label}", result))


if __name__ == "__main__":
    main()
