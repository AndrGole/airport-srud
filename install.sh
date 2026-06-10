#!/bin/bash

# =====================================================
# Установочный скрипт для Airport SRUD (СКУД аэропорта)
# =====================================================

set -e  # Останавливаем скрипт при любой ошибке

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Начинаю установку Airport SRUD...${NC}"

# 1. Обновляем систему и ставим базовые пакеты
echo -e "${YELLOW}Устанавливаю системные зависимости...${NC}"
apt update
apt install -y python3 python3-pip python3-venv nginx git screen curl

# 2. Проверяем, что мы в нужной папке (рядом с install.sh)
cd "$(dirname "$0")"

# 3. Создаём виртуальное окружение
echo -e "${YELLOW}Создаю виртуальное окружение...${NC}"
python3 -m venv venv

# 4. Активируем и ставим зависимости
echo -e "${YELLOW}Устанавливаю Python-пакеты...${NC}"
source venv/bin/activate
pip install --upgrade pip
pip install -r backend/requirements.txt

# 5. Создаём папку для фронта (на всякий случай)
mkdir -p frontend

# 6. Настраиваем права
chmod +x deploy.sh 2>/dev/null || true

# 7. Проверяем, создалась ли база данных
echo -e "${YELLOW}Инициализирую базу данных...${NC}"
cd backend
python -c "from main import init_db; init_db()" 2>/dev/null || echo "База создастся при первом запуске"

cd ..

echo -e "${GREEN}Установка завершена!${NC}"
echo -e "${GREEN}Дальше: запусти ./run.sh или ./deploy.sh${NC}"