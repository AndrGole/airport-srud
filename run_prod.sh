#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
pkill -f "python3 main.py" 2>/dev/null || true
screen -dmS airport-srud bash -c "cd $(pwd)/backend && python main.py"
echo "Сервер запущен в screen-сессии 'airport-srud'"