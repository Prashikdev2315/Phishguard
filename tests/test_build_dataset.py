import pandas as pd

from ml.build_dataset import (
    LABELS,
    add_normalization,
    apply_domain_cap,
    deduplicate,
    grouped_holdout,
)


def test_deduplicate_removes_exact_and_normalized_duplicates():
    frame = pd.DataFrame(
        [
            {"URL": "https://example.com/a", "type": "Benign"},
            {"URL": "https://example.com/a", "type": "Benign"},
            {"URL": "https://EXAMPLE.com/a", "type": "Benign"},
        ]
    )
    normalized = add_normalization(frame)
    cleaned, stats, conflicts = deduplicate(normalized)
    assert conflicts.empty
    assert len(cleaned) == 1
    assert stats["exact_duplicates_dropped"] == 1
    assert stats["normalized_duplicates_dropped"] == 1


def test_deduplicate_rejects_conflicting_labels():
    frame = pd.DataFrame(
        [
            {"URL": "https://example.com/login", "type": "Benign"},
            {"URL": "https://EXAMPLE.com/login", "type": "Malicious"},
        ]
    )
    normalized = add_normalization(frame)
    _, _, conflicts = deduplicate(normalized)
    assert not conflicts.empty
    assert set(conflicts["type"]) == {"Benign", "Malicious"}


def test_domain_cap_is_per_class_and_deterministic():
    rows = []
    for label, domain, count in [
        ("Benign", "benign-example.com", 80),
        ("Malicious", "malicious-example.net", 80),
    ]:
        for index in range(count):
            rows.append({
                "URL": f"https://{domain}/page-{index}",
                "type": label,
                "norm_url": f"http://{domain}/page-{index}",
                "registrable_domain": domain,
            })
    frame = pd.DataFrame(rows)
    first, no_domain, stats = apply_domain_cap(frame, seed=42)
    second, _, _ = apply_domain_cap(frame, seed=42)
    assert no_domain.empty
    assert len(first[first["type"] == "Benign"]) == 50
    assert len(first[first["type"] == "Malicious"]) == 50
    assert first["norm_url"].tolist() == second["norm_url"].tolist()
    assert stats["Benign"]["rows_dropped_by_cap"] == 30
    assert stats["Malicious"]["rows_dropped_by_cap"] == 30


def test_grouped_holdout_has_no_domain_overlap():
    rows = []
    for index in range(100):
        label = "Benign" if index % 2 == 0 else "Malicious"
        domain = f"site-{index}.{ 'com' if label == 'Benign' else 'net'}"
        rows.append({
            "URL": f"https://{domain}/",
            "type": label,
            "norm_url": f"http://{domain}/",
            "registrable_domain": domain,
        })
    frame = pd.DataFrame(rows)
    train, test = grouped_holdout(frame, seed=42)
    assert set(train["registrable_domain"]).isdisjoint(set(test["registrable_domain"]))
    assert len(train) + len(test) == len(frame)


def test_domain_cap_a_benign_capped_at_5():
    rows = []
    for index in range(20):
        rows.append({
            "URL": f"https://example.com/page-{index}",
            "type": "Benign",
            "source": "A_benign",
            "norm_url": f"http://example.com/page-{index}",
            "registrable_domain": "example.com",
        })
    frame = pd.DataFrame(rows)
    capped, _, _ = apply_domain_cap(frame, seed=42)
    assert len(capped) == 5
