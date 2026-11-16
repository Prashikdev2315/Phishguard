import numpy as np

from ml.robustness import AUGMENTATION_VARIANTS, augment_training_rows


def test_augmentation_is_limited_to_training_source_indices():
    urls = ["https://one.example/login", "https://two.example/account"]
    labels = np.array([1, 0])

    augmented_urls, augmented_labels, metadata = augment_training_rows(
        urls, labels, source_indices=[0]
    )

    assert len(augmented_urls) == 1 + len(AUGMENTATION_VARIANTS)
    assert set(item["source_index"] for item in metadata) == {0}
    assert set(augmented_labels.tolist()) == {1}
    assert not any("two.example" in url for url in augmented_urls)


def test_augmentation_applies_each_transform_to_both_classes():
    urls = ["https://one.example/login", "https://two.example/account"]
    labels = np.array([1, 0])

    _, augmented_labels, metadata = augment_training_rows(
        urls, labels, source_indices=[0, 1]
    )

    for source_index, label in enumerate(labels):
        variants = [
            item["variant"]
            for item in metadata
            if item["source_index"] == source_index
        ]
        assert set(variants) == {"original", *AUGMENTATION_VARIANTS}
        assert (augmented_labels[
            [item["source_index"] == source_index for item in metadata]
        ] == label).all()
