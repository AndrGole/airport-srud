#!/bin/bash

# Настройки (ПОМЕНЯЙ НА СВОИ)
SERVER_USER="your_username"
SERVER_IP="your_server_ip"
SERVER_PORT="22"
REMOTE_PATH="/home/$SERVER_USER/airport-srud"

echo "🚀 Starting deployment to $SERVER_IP..."

# Копируем бэкенд
echo "📁 Copying backend..."
scp -P $SERVER_PORT backend/main.py backend/requirements.txt $SERVER_USER@$SERVER_IP:$REMOTE_PATH/backend/

# Копируем фронтенд
echo "🎨 Copying frontend..."
scp -P $SERVER_PORT frontend/index.html $SERVER_USER@$SERVER_IP:$REMOTE_PATH/frontend/

# Подключаемся по SSH и запускаем
echo "🔧 Setting up server..."
ssh -p $SERVER_PORT $SERVER_USER@$SERVER_IP << EOF
    cd $REMOTE_PATH
    cd backend
    pip3 install --user -r requirements.txt
    # Убиваем старый процесс если есть
    pkill -f "uvicorn main:app" || true
    # Запускаем в screen
    screen -dmS airport-backend uvicorn main:app --host 0.0.0.0 --port 8000
    echo "✅ Backend started on port 8000"
EOF

echo "✅ Deployment complete!"
echo "🌐 Frontend: http://$SERVER_IP/frontend/index.html"
echo "📚 API Docs: http://$SERVER_IP:8000/docs"