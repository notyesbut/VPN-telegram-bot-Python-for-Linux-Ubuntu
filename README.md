# Rotebal VPN Bot

🛡️ **Продвинутый Telegram VPN-бот с поддержкой множественных протоколов и DPI обходом**

Rotebal VPN Bot - это полнофункциональный VPN-бот для Telegram с поддержкой WireGuard, ShadowSocks, V2Ray и Trojan протоколов. Бот включает систему платежей через TON Blockchain, реферальную программу и использует банковские порты для обхода DPI блокировок.

**Создан и поддерживается [Rotebal.com](https://rotebal.com)**

## 🚀 Особенности

- **4 VPN протокола**: WireGuard, ShadowSocks, V2Ray, Trojan
- **DPI обход**: Использование банковских портов (443, 465, 993, 8443, 1521)
- **TON платежи**: Автоматическая обработка платежей через TON Blockchain
- **Реферальная система**: 10% комиссия с платежей рефералов
- **Временные конфигурации**: Бесплатные 30-минутные пробные периоды
- **QR коды**: Автоматическая генерация QR кодов для всех конфигураций
- **Многоуровневая админка**: Система администрирования
- **Rate limiting**: Защита от спама
- **База данных**: SQLite с WAL режимом для производительности

## 📋 Требования

### Системные требования
- **ОС**: Ubuntu 20.04+ / Debian 11+ / CentOS 8+
- **RAM**: Минимум 1GB, рекомендуется 2GB+
- **CPU**: 1 vCore+
- **Диск**: 10GB+ свободного места
- **Сеть**: Статический IP адрес

### Программное обеспечение
- Python 3.8+
- WireGuard
- ShadowSocks-libev
- V2Ray
- Trojan-Go
- Nginx (опционально)
- SSL сертификат

## 🔧 Установка

### 1. Подготовка сервера

```bash
# Обновление системы
sudo apt update && sudo apt upgrade -y

# Установка базовых пакетов
sudo apt install -y curl wget git python3 python3-pip python3-venv \
    build-essential software-properties-common apt-transport-https

# Установка WireGuard
sudo apt install -y wireguard wireguard-tools

# Установка ShadowSocks
sudo apt install -y shadowsocks-libev

# Добавление репозитория для новых версий
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
```

### 2. Установка V2Ray

```bash
# Официальная установка V2Ray
curl -Ls https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh | sudo bash

# Или через snap (альтернативный способ)
sudo snap install v2ray-core
```

### 3. Установка Trojan-Go

```bash
# Скачивание последней версии Trojan-Go
cd /tmp
wget https://github.com/p4gefau1t/trojan-go/releases/latest/download/trojan-go-linux-amd64.zip
unzip trojan-go-linux-amd64.zip

# Установка
sudo mv trojan-go /usr/local/bin/
sudo chmod +x /usr/local/bin/trojan-go

# Создание конфигурационной директории
sudo mkdir -p /etc/trojan-go
```

### 4. Настройка SSL сертификатов

```bash
# Установка Certbot
sudo apt install -y certbot

# Получение SSL сертификата (замените на ваш домен)
sudo certbot certonly --standalone -d de.rotebal.com

# Или используйте DNS challenge для wildcard
sudo certbot certonly --manual --preferred-challenges dns -d "*.rotebal.com"
```

### 5. Установка Python зависимостей

```bash
# Создание пользователя для бота
sudo useradd -m -s /bin/bash vpnbot

# Переключение на пользователя vpnbot
sudo su - vpnbot

# Создание виртуального окружения
python3 -m venv /home/vpnbot/venv
source /home/vpnbot/venv/bin/activate

# Установка зависимостей
pip install --upgrade pip
pip install python-telegram-bot aiohttp aiosqlite qrcode[pil] Pillow
```

### 6. Загрузка и настройка бота

```bash
# Создание директорий
sudo mkdir -p /opt/rotebal-bot
sudo mkdir -p /etc/vpnbot
sudo mkdir -p /var/log/vpnbot
sudo mkdir -p /var/lib/vpnbot

# Установка прав
sudo chown -R vpnbot:vpnbot /opt/rotebal-bot /etc/vpnbot /var/log/vpnbot /var/lib/vpnbot

# Загрузка кода бота
cd /opt/rotebal-bot
wget https://rotebal.com/downloads/rotebal_bot.py
# Или скопируйте файл вручную

# Установка прав на выполнение
chmod +x rotebal_bot.py
```

## ⚙️ Конфигурация

### 1. Настройка WireGuard

```bash
# Создание серверного ключа
sudo su -
cd /etc/wireguard
wg genkey | tee server_private.key | wg pubkey > server_public.key

# Создание конфигурации сервера
cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = $(cat server_private.key)
Address = 10.66.66.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

EOF

# Замените eth0 на ваш сетевой интерфейс
ip route | grep default
```

### 2. Настройка ShadowSocks

```bash
# Создание конфигурации ShadowSocks
sudo mkdir /etc/shadowsocks-libev

sudo cat > /etc/shadowsocks-libev/config.json << EOF
{
    "server": "0.0.0.0",
    "server_port": 8388,
    "method": "chacha20-ietf-poly1305",
    "timeout": 300,
    "fast_open": false,
    "manager_address": "127.0.0.1",
    "manager_port": 4000
}
EOF
```

### 3. Настройка V2Ray

```bash
# Создание конфигурации V2Ray
sudo cat > /etc/v2ray/config.json << EOF
{
  "inbounds": [
    {
      "port": 443,
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/ssl/certs/rotebal.crt",
              "keyFile": "/etc/ssl/private/rotebal.key"
            }
          ]
        },
        "wsSettings": {
          "path": "/api/v1/users/"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
```

### 4. Настройка Trojan-Go

```bash
# Создание конфигурации Trojan-Go
sudo cat > /etc/trojan-go/config.json << EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 443,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": [],
    "ssl": {
        "cert": "/etc/ssl/certs/rotebal.crt",
        "key": "/etc/ssl/private/rotebal.key",
        "sni": "de.rotebal.com"
    },
    "websocket": {
        "enabled": true,
        "path": "/api/v1/users/",
        "hostname": "de.rotebal.com"
    }
}
EOF
```

## 🔑 Настройка бота

### 1. Создание Telegram бота

1. Откройте [@BotFather](https://t.me/botfather) в Telegram
2. Отправьте `/newbot`
3. Следуйте инструкциям для создания бота
4. Сохраните полученный **Bot Token**

### 2. Настройка TON кошелька

1. Установите [Tonkeeper](https://tonkeeper.com/) или [TON Wallet](https://wallet.ton.org/)
2. Создайте новый кошелек
3. **ВАЖНО**: Сохраните seed-фразу в безопасном месте
4. Скопируйте адрес кошелька
5. Получите API ключ на [toncenter.com](https://toncenter.com/api/v2/)

### 3. Обновление конфигурации в коде

Отредактируйте файл `rotebal_bot.py`:

```python
class Config:
    # Токен вашего бота
    BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"
    
    # Путь к базе данных
    DB_PATH = "/etc/vpnbot/vpnbot.db"
    
    # ID администраторов (ваш Telegram ID)
    ADMIN_IDS = [YOUR_TELEGRAM_ID]

    # TON конфигурация
    TON_WALLET_ADDRESS = "YOUR_TON_WALLET_ADDRESS"
    TON_API_KEY = "YOUR_TON_API_KEY"
    TON_API_URL = "https://toncenter.com/api/v2/"

    # Домен конфигурация
    PRIMARY_DOMAIN = "rotebal.com"

    # WireGuard конфигурация
    WG_SERVER_PRIVATE_KEY = "YOUR_WG_PRIVATE_KEY"

    # SSL сертификаты
    CERT_PATH = "/etc/letsencrypt/live/de.rotebal.com/fullchain.pem"
    CERT_KEY_PATH = "/etc/letsencrypt/live/de.rotebal.com/privkey.pem"

    # Конфигурация серверов
    SERVERS = [
        ServerConfig(
            id="de1",
            name="🇩🇪 Frankfurt Banking",
            ip="YOUR_SERVER_IP",
            domain="de.rotebal.com",
            location="Frankfurt, Germany",
            banking_ports=[443, 465, 993, 8443, 1521]
        )
    ]
```

### 4. Получение Telegram ID

```bash
# Временно добавьте этот код в бота для получения своего ID
async def get_my_id(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    await update.message.reply_text(f"Ваш Telegram ID: {user_id}")

# Добавьте в main():
app.add_handler(CommandHandler("myid", get_my_id))
```

## 🚀 Запуск

### 1. Создание systemd сервисов

#### Rotebal Bot Service

```bash
sudo cat > /etc/systemd/system/rotebal-bot.service << EOF
[Unit]
Description=Rotebal VPN Bot
After=network.target

[Service]
Type=simple
User=vpnbot
Group=vpnbot
WorkingDirectory=/opt/rotebal-bot
Environment=PATH=/home/vpnbot/venv/bin
ExecStart=/home/vpnbot/venv/bin/python /opt/rotebal-bot/rotebal_bot.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
```

#### WireGuard Service

```bash
sudo systemctl enable wg-quick@wg0
```

#### ShadowSocks Service

```bash
sudo cat > /etc/systemd/system/shadowsocks-manager.service << EOF
[Unit]
Description=Shadowsocks Manager
After=network.target

[Service]
Type=forking
User=nobody
Group=nogroup
ExecStart=/usr/bin/ss-manager -c /etc/shadowsocks-libev/config.json -u
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
```

### 2. Настройка firewall

```bash
# UFW конфигурация
sudo ufw allow ssh
sudo ufw allow 443/tcp
sudo ufw allow 465/tcp
sudo ufw allow 993/tcp
sudo ufw allow 8443/tcp
sudo ufw allow 1521/tcp
sudo ufw allow 51820/udp
sudo ufw allow 8388/tcp
sudo ufw --force enable

# Включение IP forwarding
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv6.conf.all.forwarding=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### 3. Запуск сервисов

```bash
# Запуск всех сервисов
sudo systemctl daemon-reload
sudo systemctl enable --now rotebal-bot
sudo systemctl enable --now shadowsocks-manager
sudo systemctl enable --now wg-quick@wg0
sudo systemctl enable --now v2ray
sudo systemctl enable --now trojan-go

# Проверка статуса
sudo systemctl status rotebal-bot
sudo systemctl status shadowsocks-manager
sudo systemctl status wg-quick@wg0
```

## 📊 Мониторинг и логи

### Просмотр логов

```bash
# Логи бота
sudo journalctl -u rotebal-bot -f

# Логи ShadowSocks
sudo journalctl -u shadowsocks-manager -f

# Логи WireGuard
sudo journalctl -u wg-quick@wg0 -f

# Файловые логи бота
tail -f /var/log/vpnbot/vpnbot.log
```

### Мониторинг системы

```bash
# Использование ресурсов
htop

# Сетевые соединения
sudo netstat -tulpn | grep -E '(443|465|993|8443|1521|51820|8388)'

# Проверка работы WireGuard
sudo wg show

# Статус базы данных
sudo -u vpnbot sqlite3 /etc/vpnbot/vpnbot.db ".tables"
```

## 🔧 Обслуживание

### Резервное копирование

```bash
#!/bin/bash
# backup.sh
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/var/backups/rotebal"

mkdir -p $BACKUP_DIR

# Бэкап базы данных
cp /etc/vpnbot/vpnbot.db $BACKUP_DIR/vpnbot_$DATE.db

# Бэкап конфигураций
tar -czf $BACKUP_DIR/configs_$DATE.tar.gz \
    /etc/wireguard/ \
    /etc/shadowsocks-libev/ \
    /etc/v2ray/ \
    /etc/trojan-go/ \
    /opt/rotebal-bot/

# Удаление старых бэкапов (старше 30 дней)
find $BACKUP_DIR -type f -mtime +30 -delete
```

### Обновление

```bash
# Остановка сервиса
sudo systemctl stop rotebal-bot

# Создание бэкапа
sudo cp /opt/rotebal-bot/rotebal_bot.py /opt/rotebal-bot/rotebal_bot.py.bak

# Загрузка нового кода с Rotebal.com
wget -O /opt/rotebal-bot/rotebal_bot.py https://rotebal.com/downloads/rotebal_bot.py

# Запуск сервиса
sudo systemctl start rotebal-bot

# Проверка статуса
sudo systemctl status rotebal-bot
```

### Очистка базы данных

```bash
# Подключение к базе данных
sudo -u vpnbot sqlite3 /etc/vpnbot/vpnbot.db

-- Удаление истекших конфигураций
DELETE FROM configs WHERE expires_at < datetime('now') AND expires_at IS NOT NULL;

-- Удаление старых платежей
DELETE FROM payments WHERE created_at < datetime('now', '-90 days');

-- Оптимизация базы данных
VACUUM;
```

## 🛠️ Устранение неполадок

### Общие проблемы

#### Бот не отвечает
```bash
# Проверьте статус
sudo systemctl status rotebal-bot

# Проверьте логи
sudo journalctl -u rotebal-bot -n 50

# Проверьте токен бота
curl -s "https://api.telegram.org/bot<YOUR_TOKEN>/getMe"
```

#### Ошибки базы данных
```bash
# Проверьте права доступа
ls -la /etc/vpnbot/vpnbot.db
sudo chown vpnbot:vpnbot /etc/vpnbot/vpnbot.db

# Проверьте целостность
sudo -u vpnbot sqlite3 /etc/vpnbot/vpnbot.db "PRAGMA integrity_check;"
```

#### Проблемы с SSL
```bash
# Проверьте сертификат
sudo certbot certificates

# Обновите сертификат
sudo certbot renew

# Проверьте валидность
openssl x509 -in /etc/letsencrypt/live/de.rotebal.com/fullchain.pem -text -noout
```

#### WireGuard не работает
```bash
# Проверьте конфигурацию
sudo wg show
sudo wg-quick down wg0
sudo wg-quick up wg0

# Проверьте IP forwarding
sysctl net.ipv4.ip_forward
```

#### ShadowSocks не подключается
```bash
# Проверьте ss-manager
sudo netstat -tulpn | grep 4000
sudo systemctl restart shadowsocks-manager

# Проверьте порт
sudo netstat -tulpn | grep 8388
```

### Производительность

#### Оптимизация базы данных
```bash
# Настройка SQLite для производительности
sudo -u vpnbot sqlite3 /etc/vpnbot/vpnbot.db << EOF
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA cache_size=10000;
PRAGMA temp_store=memory;
EOF
```

#### Оптимизация системы
```bash
# Увеличение лимитов файлов
echo "vpnbot soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "vpnbot hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Оптимизация сети
echo 'net.core.rmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
echo 'net.core.wmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

## 🔒 Безопасность

### Базовая защита

```bash
# Отключение root SSH
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart ssh

# Настройка fail2ban
sudo apt install -y fail2ban
sudo systemctl enable --now fail2ban

# Автоматические обновления безопасности
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

### Мониторинг атак

```bash
# Установка и настройка Logwatch
sudo apt install -y logwatch
sudo logwatch --detail High --service All --range today --mailto support@rotebal.com
```

## 📞 Поддержка

### Контакты
- **Официальный сайт**: [Rotebal.com](https://rotebal.com)
- **Telegram поддержка**: @rotebal_support
- **Email**: support@rotebal.com

### Полезные команды

```bash
# Полная диагностика
sudo /opt/rotebal-bot/diagnostic.sh

# Быстрый перезапуск всех сервисов
sudo systemctl restart rotebal-bot shadowsocks-manager wg-quick@wg0 v2ray trojan-go

# Проверка всех портов
sudo netstat -tulpn | grep -E '(443|465|993|8443|1521|51820|8388|4000)'
```

## 🌟 Дополнительные ресурсы

### Официальные ссылки Rotebal.com
- **Главная страница**: https://rotebal.com

### Сообщество
- **Telegram канал**: @rotebal_news
- **Telegram чат**: @rotebal_chat

## 📄 Лицензия

MIT License

## 🙏 Благодарности

- Команда разработчиков [Rotebal.com](https://rotebal.com)
- Telegram Bot API
- TON Blockchain
- WireGuard Project
- ShadowSocks Project
- V2Ray Project
- Trojan-Go Project

---

**⚠️ Важно**: Этот бот разработан и поддерживается [Rotebal.com](https://rotebal.com) для легального использования. Убедитесь, что соблюдаете все местные законы и правила относительно VPN сервисов.

**🔗 Получить поддержку**: Для получения технической поддержки и консультаций посетите [Rotebal.com](https://rotebal.com) или свяжитесь с нашей службой поддержки.
