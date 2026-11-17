"""Export the experimental TF-IDF URL model to a browser-readable JSON file."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from ml.tfidf_model import train_tfidf_model


def export_model(train_path: Path, output_path: Path) -> None:
    frame = pd.read_csv(train_path, dtype=str, keep_default_na=False)
    model = train_tfidf_model(frame)
    vectorizer = model.named_steps["vectorizer"]
    classifier = model.named_steps["classifier"]
    payload = {
        "schema": "tfidf-url-v1",
        "ngram_min": 3,
        "ngram_max": 5,
        "vocabulary": {key: int(value) for key, value in vectorizer.vocabulary_.items()},
        "idf": vectorizer.idf_.tolist(),
        "coefficient": classifier.coef_[0].tolist(),
        "intercept": float(classifier.intercept_[0]),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, separators=(",", ":")) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--train", type=Path, default=Path("data/splits_v2/experimental/train.csv"))
    parser.add_argument("--output", type=Path, default=Path("extension/public/tfidf_model.json"))
    args = parser.parse_args()
    export_model(args.train, args.output)


if __name__ == "__main__":
    main()
