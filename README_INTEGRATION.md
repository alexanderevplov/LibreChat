# LibreChat Integration - BizNeuron

## Текущая конфигурация

LibreChat добавлен как git submodule в проект BizNeuron OpenAI Agent Platform.

### Порты и контейнеры:
- **Старый LibreChat** (из bizneuron): порт 3080, контейнер `LibreChat`
- **Новый LibreChat** (в проекте): порт 3081, контейнер `bizneuron_librechat`

### Запуск

```bash
# Запустить только LibreChat из нашего проекта
docker-compose -f docker-compose.librechat.yaml up -d

# Или запустить все сервисы вместе
docker-compose up -d

# Посмотреть логи
docker-compose -f docker-compose.librechat.yaml logs -f librechat_new
```

### Доступ
- Новый LibreChat: http://localhost:3081
- Старый LibreChat: http://localhost:3080 (можно остановить когда не нужен)

### Остановка старого LibreChat
```bash
docker stop LibreChat rag_api
```

### Обновление конфигурации
- Настройки: `librechat/.env`
- Endpoints: `librechat/librechat.yaml`

### Обновление кода LibreChat
```bash
cd librechat
git pull origin main
cd ..
git add librechat
git commit -m "Update LibreChat to latest version"
```

## Интеграция с API

Когда API будет готов, раскомментируйте в `docker-compose.librechat.yaml`:
```yaml
environment:
  - CUSTOM_ENDPOINT=http://api:8000/v1
```

## Сети Docker
Все сервисы используют сеть `bizneuron_network` для взаимодействия.