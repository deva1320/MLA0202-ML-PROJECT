"""Dataset preparation execution script for PhishGuard AI.

Loads or initializes labeled URL dataset, extracts canonical 18-dim features,
and caches the processed dataset to data/processed/features_dataset.csv.
"""

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.phishguard.data.prepare_dataset import prepare_url_dataset
from config import RAW_DATA_DIR, PROCESSED_DATA_DIR, FEATURE_CONFIG


def main():
    print("=" * 60)
    print("PhishGuard AI - Dataset Preparation & Feature Extraction")
    print("=" * 60)

    raw_path = RAW_DATA_DIR / "urls.csv"
    processed_path = PROCESSED_DATA_DIR / "features_dataset.csv"

    print(f"Loading raw dataset from {raw_path}...")
    features_df, train_df, test_df = prepare_url_dataset(
        raw_path=raw_path,
        output_path=processed_path,
        force_recompute=True
    )

    total_samples = len(features_df)
    phish_count = int(features_df["label"].sum())
    legit_count = total_samples - phish_count

    print(f"\nExtracted {len(FEATURE_CONFIG.feature_names)} features for {total_samples} URLs:")
    print(f"  - Legitimate URLs: {legit_count} ({legit_count/total_samples:.1%})")
    print(f"  - Phishing URLs:   {phish_count} ({phish_count/total_samples:.1%})")

    print(f"\nStratified 80/20 Train/Test Split:")
    print(f"  - Training Set:   {len(train_df)} samples")
    print(f"  - Held-out Test:  {len(test_df)} samples")
    print(f"\nCached features saved to: {processed_path}")
    print("Next step: Run 'python scripts/train_models.py' to fit Decision Tree and Random Forest.")
    print("=" * 60)


if __name__ == "__main__":
    main()
