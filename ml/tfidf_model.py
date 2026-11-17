"""Experimental character n-gram URL classifier."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


def build_tfidf_model() -> Pipeline:
    return Pipeline(
        [
            (
                "vectorizer",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(3, 5),
                    max_features=10_000,
                    lowercase=True,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    C=1.0,
                    class_weight="balanced",
                    max_iter=500,
                    random_state=42,
                ),
            ),
        ]
    )


def train_tfidf_model(frame: pd.DataFrame) -> Pipeline:
    """Train on a frame containing ``URL`` and ``type`` columns."""
    required = {"URL", "type"}
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")
    model = build_tfidf_model()
    model.fit(frame["URL"].astype(str), (frame["type"] == "Malicious").astype(int))
    return model


def save_tfidf_model(model: Pipeline, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)
