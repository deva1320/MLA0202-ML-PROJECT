"""Model training script for PhishGuard AI.

Loads the processed feature dataset, fits Decision Tree and Random Forest classifiers,
and persists artifacts to artifacts/.
"""

import sys
from pathlib import Path
import pandas as pd

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config import PROCESSED_DATA_DIR, ML_CONFIG, FEATURE_CONFIG
from src.phishguard.data.prepare_dataset import prepare_url_dataset
from src.phishguard.models.train import train_classifiers


def main():
    print("=" * 60)
    print("PhishGuard AI - Supervised Model Training")
    print("=" * 60)

    dataset_path = PROCESSED_DATA_DIR / "features_dataset.csv"
    if not dataset_path.exists():
        print(f"Features dataset not found at {dataset_path}. Preparing dataset now...")
        prepare_url_dataset()

    print(f"Loading processed feature dataset from {dataset_path}...")
    df = pd.read_csv(dataset_path)

    feature_names = FEATURE_CONFIG.feature_names
    total_samples = len(df)
    phish_count = int(df["label"].sum())
    legit_count = total_samples - phish_count

    print(f"Dataset summary: {total_samples} samples across {len(feature_names)} features.")
    print(f"  - Legitimate (0): {legit_count}")
    print(f"  - Phishing   (1): {phish_count}")

    # Split into train/test using reproducible random_state
    from sklearn.model_selection import train_test_split
    train_df, test_df = train_test_split(
        df,
        test_size=ML_CONFIG.test_size,
        random_state=ML_CONFIG.random_state,
        stratify=df["label"]
    )

    print(f"\nTraining set: {len(train_df)} samples | Held-out test set: {len(test_df)} samples")
    print("\nFitting Decision Tree and Random Forest classifiers with 5-Fold Stratified CV...")

    dt_pipeline, rf_pipeline, metadata = train_classifiers(
        X_train=train_df[feature_names],
        y_train=train_df["label"],
        feature_names=feature_names
    )

    print("\n" + "=" * 60)
    print("TRAINING SUCCESSFUL!")
    print("=" * 60)
    print(f"1. Decision Tree (DT):")
    print(f"   - 5-Fold CV Accuracy: {metadata['decision_tree']['cv_accuracy_mean']:.1%}")
    print(f"   - Training Latency:   {metadata['decision_tree']['fit_time_seconds']:.3f}s")
    
    print(f"\n2. Random Forest (RF):")
    print(f"   - 5-Fold CV Accuracy: {metadata['random_forest']['cv_accuracy_mean']:.1%}")
    print(f"   - Training Latency:   {metadata['random_forest']['fit_time_seconds']:.3f}s")

    print("\nTop 5 Informative Features (Random Forest Gini Impurity):")
    for f in metadata["random_forest"]["feature_importances"][:5]:
        print(f"  - {f['feature']:24s}: {f['importance']:.4f}")

    print("\nArtifacts saved to artifacts/:")
    print("  - artifacts/decision_tree.joblib")
    print("  - artifacts/random_forest.joblib")
    print("  - artifacts/model_metadata.json")
    print("\nNext step: Run 'python scripts/evaluate_models.py' to benchmark on held-out test data.")
    print("=" * 60)


if __name__ == "__main__":
    main()
