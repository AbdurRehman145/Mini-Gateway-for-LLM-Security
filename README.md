# LLM Security Gateway

## Project Overview
This repository contains the code, documentation, and automated evaluation suite for a modular **LLM Security Gateway**. Large Language Models (LLMs) are highly vulnerable to prompt injection, jailbreaking, and the leakage of Personally Identifiable Information (PII). 

This gateway acts as a defensive middleware layer. It intercepts user inputs, analyzes them for malicious intent or sensitive data, and applies strict routing policies (ALLOW, MASK, or BLOCK) before the prompt ever reaches the LLM.

## System Architecture
The gateway is built with a strictly modular, object-oriented pipeline consisting of three primary modules:

1. **Injection Detection Module:** Defends against direct prompt injections and jailbreaks (e.g., "DAN" prompts). It uses a hybrid approach:
   * **Weighted Regular Expressions:** For exact structural matches of known attacks.
   * **Fuzzy String Matching:** Utilizes `thefuzz` library to calculate Levenshtein distance, catching intentional typos and obfuscation attempts (e.g., "igore previus instructons").
2. **PII Detection Module (Custom Presidio):** Wraps Microsoft Presidio to detect and anonymize sensitive data. It includes three major enterprise customizations:
   * **Custom Recognizers:** Regex-based detection for internal AWS-style API keys (`AKIA...`).
   * **Context-Aware Scoring:** Automatically boosts confidence scores if context words (like "secret" or "token") appear near suspected keys.
   * **Confidence Calibration:** Forces aggressive confidence scores (0.95) for highly specific composite matches to guarantee redaction.
3. **Policy Engine:** Evaluates the `injection_score` and `max_pii_score` against configurable numerical thresholds to make a final routing decision.

## Prerequisites
To run this project, you will need:
* **Python 3.8-3.12** installed on your system.
* **Git** (to clone the repository).

---

## Environment Setup & Installation

To ensure full reproducibility, please follow these exact steps to configure your environment and install the required dependencies.

**1. Clone the repository**  
Open your terminal and run: 
```bash
git clone https://github.com/AbdurRehman145/Mini-Gateway-for-LLM-Security
cd Mini-Gateway-for-LLM-Security
```

**2. Create a Virtual Environment**  
On Windows:
```bash
python -m venv venv
venv\Scripts\activate
```

On macOS and Linux:
```bash
python3 -m venv venv
source venv/bin/activate
```

**3. Install Dependencies**
```bash
pip install -r requirements.txt
```

**4. Download the NLP Language Model**
```bash
python -m spacy download en_core_web_lg
```

**5. Run th Code**
```bash
python main.py
```