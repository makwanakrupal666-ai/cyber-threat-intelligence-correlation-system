#!/usr/bin/env bash
# Run this once: python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
# This script just starts the API server.
set -e
source .venv/bin/activate
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
