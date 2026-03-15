#!/usr/bin/env bash

TOOLS_DIR="$(cd "$(dirname "$0")" && pwd)/tools"
mkdir -p "$TOOLS_DIR"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run with sudo:"
  echo "sudo ./install.sh"
  exit 1
fi

echo "Installing packages..."
apt update -y
apt install -y \
 python3 python3-venv python3-pip \
 sudo curl ca-certificates \
 libcap2-bin \
 nmap masscan zmap nikto whatweb wpscan \
 rkhunter chkrootkit lynis clamav \
 bandit trufflehog golang git testssl.sh

echo "Configuring capabilities for raw-socket scanners (best-effort)..."
setcap cap_net_raw,cap_net_admin+eip "$(command -v zmap)" 2>/dev/null || true
setcap cap_net_raw,cap_net_admin+eip "$(command -v masscan)" 2>/dev/null || true

echo "Downloading LinEnum..."
  curl -L https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -o "$TOOLS_DIR/LinEnum.sh"
  chmod +x "$TOOLS_DIR/LinEnum.sh"

echo "Downloading linpeas..."
  curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o "$TOOLS_DIR/linpeas.sh"
  chmod +x "$TOOLS_DIR/linpeas.sh"

echo "Installing scanners..."

  apt update -y
  apt install -y curl wget python3-pip golang-go trivy

# dalfox
  go install github.com/hahwul/dalfox/v2@latest
  cp ~/go/bin/dalfox /usr/local/bin/

# nuclei
  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  cp ~/go/bin/nuclei /usr/local/bin/
  nuclei -update-templates


echo "Done installing scanners"

echo "Tip: Tools like rkhunter/lynis/chkrootkit still need root."
echo "If you run the server as a normal user, it will try 'sudo -n' for those tools."
echo "Configure passwordless sudo for them if needed."

echo "Done."
ls -lh "$TOOLS_DIR"