## Setup

```bash
sudo apt update -y
chmod +x install.sh
sudo ./install.sh

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run

### Recommended 
Root-required tools will be executed via `sudo -n` (non-interactive). If your sudo prompts
for a password, the tool will fail and you'll see the reason in the **Errors** tab.

```bash
source venv/bin/activate
python -m uvicorn app:app --host 0.0.0.0 --port 8000
```
