# PromptDefender
 


## Project Structure


promptDefender_firstLayer/
├── detector.py
├── phases/
│ ├── malicious_detector.py
│ └── structure_detector.py
├── rules/
│ ├── malicious_patterns.py
│ └── policy_patterns.py
└── Tests/
├── data/
│ └── Prompt_INJECTION_And_Benign_DATASET.jsonl
├── errors.jsonl
└── test1.ipynb


---

## Requirements

- Python 3.10 or higher  
- pip  

Install dependencies:

```bash
pip install notebook
```


## Running Tests

Open the Jupyter Notebook:

Tests/test1.ipynb

Run all cells to evaluate the detection system.


## Detection Pipeline

### Malicious Detection
- **File:** `phases/malicious_detector.py`
- **Uses:** `rules/malicious_patterns.py`
- **Detects:**
  - Jailbreaking attempts
  - Instruction override attacks
  - Data exfiltration patterns
### Structure Detection
- **File:** `phases/structure_detector.py`
- **Uses:** `rules/policy_patterns.py`
- **Detects:**
  - Suspicious structures
  - Hidden instructions
  - Policy violations

---
The outputs of both phases are combined to classify prompts as:
Benign
Suspicious / Malicious
## Dataset
**Location**: Tests/data/Prompt_INJECTION_And_Benign_DATASET.jsonl
**Contains:**
 -Benign prompts
 -Prompt injection examples
 -Expected outputs
 
Errors and flagged prompts are stored in: Tests/errors.jsonl

---
