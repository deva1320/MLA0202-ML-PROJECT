"""Environment verification script for PhishGuard AI.

Checks Python version, installed ML and web dependencies, and project directories.
"""

import sys
import importlib
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

REQUIRED_PACKAGES = {
    "numpy": "1.24.0",
    "pandas": "2.0.0",
    "sklearn": "1.3.0",
    "joblib": "1.3.0",
    "streamlit": "1.30.0",
    "plotly": "5.18.0",
    "matplotlib": "3.8.0",
    "pytest": "7.4.0",
}


def check_python_version() -> bool:
    print("=" * 60)
    print("PhishGuard AI - Environment Diagnostics")
    print("=" * 60)
    py_ver = sys.version_info
    print(f"Python: {py_ver.major}.{py_ver.minor}.{py_ver.micro} ({sys.executable})")
    if py_ver.major == 3 and py_ver.minor in (11, 12, 13):
        print("  [OK] Supported Python version.")
        return True
    else:
        print("  [WARN] Python 3.11 is recommended.")
        return True


def check_packages() -> bool:
    print("\nChecking Required Packages:")
    all_ok = True
    for pkg_name, min_ver in REQUIRED_PACKAGES.items():
        try:
            mod = importlib.import_module(pkg_name)
            ver = getattr(mod, "__version__", "unknown")
            print(f"  [OK] {pkg_name:15s} (installed: {ver}, required: >={min_ver})")
        except ImportError:
            print(f"  [FAIL] {pkg_name:15s} MISSING! Please run: pip install -r requirements.txt")
            all_ok = False
    return all_ok


def check_directories() -> bool:
    print("\nChecking Project Directories:")
    required_dirs = [
        "data/raw",
        "data/processed",
        "artifacts",
        "pages",
        "src/phishguard",
        "tests",
        "assets/styles"
    ]
    all_ok = True
    for d in required_dirs:
        p = PROJECT_ROOT / d
        if p.exists() and p.is_dir():
            print(f"  [OK] {d}")
        else:
            print(f"  [MISSING] {d} - creating...")
            p.mkdir(parents=True, exist_ok=True)
    return all_ok


def check_model_artifacts() -> None:
    print("\nChecking Model Artifacts:")
    dt_path = PROJECT_ROOT / "artifacts" / "decision_tree.joblib"
    rf_path = PROJECT_ROOT / "artifacts" / "random_forest.joblib"
    meta_path = PROJECT_ROOT / "artifacts" / "model_metadata.json"
    
    if dt_path.exists() and rf_path.exists() and meta_path.exists():
        print(f"  [OK] Trained Decision Tree artifact found: {dt_path.name}")
        print(f"  [OK] Trained Random Forest artifact found:  {rf_path.name}")
    else:
        print("  [INFO] Trained models not yet generated. Run 'python scripts/train_models.py'.")


def main():
    py_ok = check_python_version()
    pkg_ok = check_packages()
    dir_ok = check_directories()
    check_model_artifacts()
    
    print("\n" + "=" * 60)
    if py_ok and pkg_ok and dir_ok:
        print("SUCCESS: Environment is fully configured for PhishGuard AI!")
    else:
        print("NOTICE: Please resolve missing dependencies above before continuing.")
    print("=" * 60)


if __name__ == "__main__":
    main()
