# Ubuntu Linux Real-Audit Procedure

Run this only on an isolated Ubuntu test VM that the operator is authorized to
modify.

```bash
sudo apt update
sudo apt install -y python3 python3-venv
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-core.txt
bash scripts/ubuntu_linux_audit_test.sh
```

The script prompts for the two controlled passwords without placing them in
shell command arguments or log output. It uses `chpasswd` over standard input,
creates disposable accounts, invokes the real `/etc/passwd` and `/etc/shadow`
audit path, writes reports to a temporary directory, and removes the accounts
and temporary files.

The script requires `python3 main.py audit-linux` to produce:

- A weak finding for `younes`
- A no-match or explicitly unsupported result for `younesalsalami`
- The actual algorithm name
- Extracted salt metadata
- The `/etc/shadow` audit source
- No plaintext password values

This procedure is an acceptance test. It must not be represented as passed
unless it is executed on Ubuntu and its reports are retained as evidence.
