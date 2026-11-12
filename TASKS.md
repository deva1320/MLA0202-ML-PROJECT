# PhishGuard AI — Task Tracking

Legend:
- [x] Completed and verified
- [/] In progress
- [ ] Planned / Not started

---

## Stage 1: Workspace & Backup
- [x] Inspect workspace and locate old music project files
- [x] Create timestamped backup in `backup_previous_music_project/`
- [x] Initialize new `PhishGuard-AI` project directory and Git repository
- [x] Create project structure matching ML capstone requirements

## Stage 2: Environment & Dependencies
- [x] Initialize Python 3.11 virtual environment in `PhishGuard-AI/.venv`
- [x] Create `requirements.txt` with verified ML & web packages
- [x] Create `config.py`, `.gitignore`, `.env.example`, `pytest.ini`, and `pyproject.toml`
- [x] Create `scripts/check_environment.py` and verify dependencies

## Stage 3: Dataset Preparation & Feature Extraction
- [x] Implement canonical 18-dim URL feature extractor (`src/phishguard/features/url_features.py`)
- [x] Implement input validation and URL normalization (`src/phishguard/utils/validation.py`)
- [x] Ingest genuine benchmark labeled URL dataset in `scripts/prepare_dataset.py`
- [x] Extract canonical features and generate clean train/test split in `data/processed/`

## Stage 4: Supervised ML Classifiers & Evaluation
- [x] Implement Decision Tree and Random Forest training pipeline (`src/phishguard/models/train.py`)
- [x] Implement model evaluation and metric benchmarking (`src/phishguard/models/evaluate.py`)
- [x] Implement inference service with prediction policy (`src/phishguard/services/url_analyzer.py`)
- [x] Run `scripts/train_models.py` and `scripts/evaluate_models.py` to persist artifacts

## Stage 5: Multi-Page Web Application
- [x] Create cybersecurity dark theme styles (`assets/styles/main.css`)
- [x] Implement Home / URL Scanner (`app.py`)
- [x] Implement URL Feature Analysis page (`pages/1_URL_Feature_Analysis.py`)
- [x] Implement Model Comparison page (`pages/2_Model_Comparison.py`)
- [x] Implement About Project page (`pages/3_About_Project.py`)

## Stage 6: Testing, Documentation & Handover
- [x] Implement automated pytest suites (`tests/test_url_features.py`, `tests/test_validation.py`, `tests/test_training.py`, `tests/test_prediction.py`)
- [x] Verify test suite execution (`pytest -v` -> 22/22 passed)
- [x] Verify Streamlit app startup
- [x] Write comprehensive `README.md`
- [x] Commit clean release to Git
- [x] Deliver final engineering handover
