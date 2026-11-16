import numpy as np

from ml.evaluate import (
    apply_calibrator,
    choose_block_threshold,
    choose_warn_threshold,
    ece,
    fit_calibrator,
    generate_adversarial_urls,
)


def test_calibration_improves_or_preserves_probability_shape():
    y = np.array([0, 0, 0, 1, 1, 1] * 200)
    raw = np.array([0.05, 0.2, 0.35, 0.65, 0.8, 0.95] * 200)

    calibration = fit_calibrator(raw, y)
    calibrated = apply_calibrator(calibration, raw)

    assert calibration["method"] in {"platt", "isotonic"}
    assert np.isfinite(calibrated).all()
    assert ((calibrated >= 0.0) & (calibrated <= 1.0)).all()
    assert ece(y, calibrated) <= ece(y, raw) + 1e-12


def test_threshold_selection_obeys_gate_constraints():
    y = np.array([0] * 100 + [1] * 100)
    probabilities = np.array([0.01] * 95 + [0.8] * 5 + [0.2] * 5 + [0.9] * 95)

    block = choose_block_threshold(y, probabilities, maximum_fpr=0.005)
    warn = choose_warn_threshold(y, probabilities, minimum_recall=0.90, maximum_fpr=0.05)

    assert block is not None
    assert warn is not None
    assert block >= warn


def test_adversarial_generation_is_deterministic_and_preserves_sources():
    variants = generate_adversarial_urls(["https://example.com/login"])

    assert len(variants) == 4
    assert {item["source_url"] for item in variants} == {"https://example.com/login"}
    assert {item["variant"] for item in variants} == {
        "benign_path_token",
        "brand_subdomain",
        "hyphen_digit_host",
        "long_path",
    }
