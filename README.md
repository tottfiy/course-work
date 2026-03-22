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

```bash
source venv/bin/activate
python -m uvicorn app:app --host 0.0.0.0 --port 8000
```
