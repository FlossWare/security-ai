#!/bin/bash
# Install security-ai from GitHub
set -e
pip install "git+https://github.com/FlossWare/security-ai.git"
echo "security-ai installed successfully."
python3 -c "from security_ai import __version__; print(f'  Version: {__version__}')"
