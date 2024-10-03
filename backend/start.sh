#!/bin/sh
uvicorn your_module_name:app --host 0.0.0.0 --port $PORT --reload
