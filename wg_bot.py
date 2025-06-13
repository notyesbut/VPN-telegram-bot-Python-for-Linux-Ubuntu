#!/usr/bin/env python3
import os
import json
import subprocess
import tempfile
import logging
import base64
import secrets
import hashlib
import qrcode
import aiohttp
import sqlite3
import aiosqlite
import asyncio
import uuid
import time
import socket
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, BotCommand
from telegram.ext import (
    ApplicationBuilder, CommandHandler, CallbackQueryHandler,
    ContextTypes, MessageHandler, filters
)

# Enhanced logging configuration
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    handlers=[
        logging.FileHandler('/var/log/vpnbot/vpnbot.log', mode='a'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# Configuration Classes
@dataclass
class ServerConfig:
    id: str
    name: str
    ip: str
    domain: str
    location: str
    interface: str = "enp1s0"
    banking_ports: List[int] = None
    max_users: int = 1000
    is_active: bool = True


@dataclass
class PriceConfig:
    ton: float
    rub: float
    usd: float


class ProtocolType(Enum):
    WIREGUARD = "wireguard"
    SHADOWSOCKS = "shadowsocks"
    V2RAY = "v2ray"
    TROJAN = "trojan"


class UserStatus(Enum):
    FREE = "free"
    PREMIUM = "premium"
    ADMIN = "admin"


class ObfuscationType(Enum):
    NONE = "none"
    TLS = "tls"
    WEBSOCKET = "websocket"


# Production Configuration
class Config:
    BOT_TOKEN = "BOT_TOKEN"
    DB_PATH = "/etc/vpnbot/vpnbot.db"
    ADMIN_IDS = [1981730098]

    # TON Configuration
    TON_WALLET_ADDRESS = "TON_WALLET_ADDRESS"
    TON_API_KEY = "TON_API_KEY"
    TON_API_URL = "https://toncenter.com/api/v2/"

    # Domain Configuration
    PRIMARY_DOMAIN = "PRIMARY_DOMAIN"

    # WireGuard Configuration
    WG_INTERFACE = "wg0"
    WG_SERVER_PRIVATE_KEY = "WG_SERVER_PRIVATE_KEY"
    WG_CONFIG_PATH = "/etc/wireguard/wg0.conf"

    # SSL Certificates
    CERT_PATH = "CERT_PATH "
    CERT_KEY_PATH = "CERT_KEY_PATH"

    # Banking ports for DPI bypass
    BANKING_PORTS = {
        443: "HTTPS/Banking",
        465: "SMTP SSL/Banking",
        993: "IMAP SSL/Banking",
        8443: "Alternative HTTPS",
        1521: "Oracle Database/Banking"
    }

    # Pricing
    PRICES = {
        "day": PriceConfig(ton=0.3, rub=25, usd=0.30),
        "week": PriceConfig(ton=1.5, rub=100, usd=1.20),
        "month": PriceConfig(ton=5.0, rub=300, usd=3.50),
        "year": PriceConfig(ton=40.0, rub=2500, usd=30.0)
    }

    # Server Configuration
    SERVERS = [
        ServerConfig(
            id="de1",
            name="🇩🇪 Frankfurt Banking",
            ip="45.77.77.77",
            domain="de.rotebal.com",
            location="Frankfurt, Germany",
            banking_ports=[443, 465, 993, 8443, 1521]
        )
    ]

    # Free user limits
    FREE_DAILY_MINUTES = 30
    TEMP_CONFIG_LIFETIME = 30


# Database Manager
class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path

    async def init_database(self):
        """Initialize database with proper schema and migrations"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        async with aiosqlite.connect(self.db_path) as conn:
            # Enable WAL mode for better performance
            await conn.execute("PRAGMA journal_mode=WAL")
            await conn.execute("PRAGMA synchronous=NORMAL")

            # Check if users table exists
            cursor = await conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            users_table_exists = await cursor.fetchone()

            if not users_table_exists:
                # Create new users table with all columns including ss_password
                await conn.execute("""
                                   CREATE TABLE users
                                   (
                                       user_id              TEXT PRIMARY KEY,
                                       username             TEXT,
                                       first_name           TEXT,
                                       last_name            TEXT,
                                       language_code        TEXT      DEFAULT 'ru',
                                       created_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                       subscription_type    TEXT,
                                       subscription_expires TIMESTAMP,
                                       daily_usage          INTEGER   DEFAULT 0,
                                       last_usage_date      DATE,
                                       total_usage_bytes    INTEGER   DEFAULT 0,
                                       is_banned            BOOLEAN   DEFAULT FALSE,
                                       referral_code        TEXT UNIQUE,
                                       referred_by          TEXT,
                                       referral_earnings    REAL      DEFAULT 0.0,
                                       last_activity        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                       ss_password          TEXT
                                   )
                                   """)
                logger.info("Created new users table")
            else:
                # Migrate existing users table
                await self._migrate_users_table(conn)

            # Check if configs table exists
            cursor = await conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='configs'")
            configs_table_exists = await cursor.fetchone()

            if not configs_table_exists:
                # Create new configs table
                await conn.execute("""
                                   CREATE TABLE configs
                                   (
                                       id               INTEGER PRIMARY KEY AUTOINCREMENT,
                                       user_id          TEXT,
                                       protocol         TEXT,
                                       server_id        TEXT,
                                       config_data      TEXT,
                                       config_name      TEXT,
                                       obfuscation_type TEXT      DEFAULT 'none',
                                       port             INTEGER,
                                       created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                       expires_at       TIMESTAMP,
                                       last_used        TIMESTAMP,
                                       is_active        BOOLEAN   DEFAULT TRUE,
                                       usage_bytes      INTEGER   DEFAULT 0,
                                       FOREIGN KEY (user_id) REFERENCES users (user_id)
                                   )
                                   """)
                logger.info("Created new configs table")
            else:
                # Migrate existing configs table
                await self._migrate_configs_table(conn)

            # Create payments table
            await conn.execute("""
                               CREATE TABLE IF NOT EXISTS payments
                               (
                                   id
                                   TEXT
                                   PRIMARY
                                   KEY,
                                   user_id
                                   TEXT,
                                   username
                                   TEXT,
                                   subscription_type
                                   TEXT,
                                   amount
                                   REAL,
                                   currency
                                   TEXT,
                                   ton_amount
                                   REAL,
                                   status
                                   TEXT
                                   DEFAULT
                                   'pending',
                                   created_at
                                   TIMESTAMP
                                   DEFAULT
                                   CURRENT_TIMESTAMP,
                                   completed_at
                                   TIMESTAMP,
                                   expires_at
                                   TIMESTAMP,
                                   FOREIGN
                                   KEY
                               (
                                   user_id
                               ) REFERENCES users
                               (
                                   user_id
                               )
                                   )
                               """)

            # Create server stats table
            await conn.execute("""
                               CREATE TABLE IF NOT EXISTS server_stats
                               (
                                   server_id
                                   TEXT,
                                   protocol
                                   TEXT,
                                   port
                                   INTEGER,
                                   active_connections
                                   INTEGER
                                   DEFAULT
                                   0,
                                   total_bytes
                                   INTEGER
                                   DEFAULT
                                   0,
                                   last_updated
                                   TIMESTAMP
                                   DEFAULT
                                   CURRENT_TIMESTAMP,
                                   PRIMARY
                                   KEY
                               (
                                   server_id,
                                   protocol,
                                   port
                               )
                                   )
                               """)

            await conn.commit()
            logger.info("Database initialized successfully")

    async def _migrate_users_table(self, conn):
        """Migrate users table to add missing columns"""
        cursor = await conn.execute("PRAGMA table_info(users)")
        columns = await cursor.fetchall()
        existing_columns = [col[1] for col in columns]

        # Add missing columns including ss_password
        required_columns = {
            'first_name': 'TEXT',
            'last_name': 'TEXT',
            'language_code': 'TEXT DEFAULT "ru"',
            'total_usage_bytes': 'INTEGER DEFAULT 0',
            'referral_earnings': 'REAL DEFAULT 0.0',
            'last_activity': 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP',
            'ss_password': 'TEXT'
        }

        for column_name, column_type in required_columns.items():
            if column_name not in existing_columns:
                try:
                    await conn.execute(f"ALTER TABLE users ADD COLUMN {column_name} {column_type}")
                    logger.info(f"Added column {column_name} to users table")
                except Exception as e:
                    logger.warning(f"Could not add column {column_name}: {e}")

    async def _migrate_configs_table(self, conn):
        """Migrate configs table to add missing columns"""
        cursor = await conn.execute("PRAGMA table_info(configs)")
        columns = await cursor.fetchall()
        existing_columns = [col[1] for col in columns]

        # Add missing columns
        required_columns = {
            'config_name': 'TEXT',
            'obfuscation_type': 'TEXT DEFAULT "none"',
            'port': 'INTEGER',
            'last_used': 'TIMESTAMP',
            'usage_bytes': 'INTEGER DEFAULT 0'
        }

        for column_name, column_type in required_columns.items():
            if column_name not in existing_columns:
                try:
                    await conn.execute(f"ALTER TABLE configs ADD COLUMN {column_name} {column_type}")
                    logger.info(f"Added column {column_name} to configs table")
                except Exception as e:
                    logger.warning(f"Could not add column {column_name}: {e}")


# TON Payment Manager
class TONPaymentManager:
    def __init__(self, api_key: str, wallet_address: str):
        self.api_key = api_key
        self.wallet_address = wallet_address
        self.api_url = Config.TON_API_URL
        self.session = None

    async def initialize(self):
        """Initialize aiohttp session"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={
                "User-Agent": "SafeZoneHub-VPN-Bot/1.0",
                "X-API-Key": self.api_key
            }
        )

    async def create_payment_request(self, user_id: str, amount: float,
                                     subscription_type: str) -> Dict[str, Any]:
        """Create payment request"""
        payment_id = f"szh_{user_id}_{int(time.time())}_{secrets.token_hex(4)}"

        # Store in database
        async with aiosqlite.connect(Config.DB_PATH) as conn:
            await conn.execute("""
                               INSERT INTO payments (id, user_id, subscription_type, ton_amount, status, created_at)
                               VALUES (?, ?, ?, ?, 'pending', ?)
                               """, (payment_id, user_id, subscription_type, amount, datetime.now()))
            await conn.commit()

        # Create payment URLs
        ton_amount_nano = int(amount * 1e9)

        return {
            "payment_id": payment_id,
            "wallet_address": self.wallet_address,
            "amount": amount,
            "amount_nano": ton_amount_nano,
            "comment": payment_id,
            "ton_url": f"ton://transfer/{self.wallet_address}?amount={ton_amount_nano}&text={payment_id}",
            "tonkeeper_url": f"https://app.tonkeeper.com/transfer/{self.wallet_address}?amount={ton_amount_nano}&text={payment_id}",
            "expires_at": (datetime.now() + timedelta(hours=24)).isoformat()
        }

    async def check_payment_status(self, payment_id: str) -> bool:
        """Check payment status via TON API"""
        if not self.session:
            await self.initialize()

        try:
            params = {
                "address": self.wallet_address,
                "limit": 50,
                "api_key": self.api_key
            }

            async with self.session.get(f"{self.api_url}getTransactions", params=params) as response:
                if response.status != 200:
                    return False

                data = await response.json()
                if not data.get("ok"):
                    return False

                transactions = data.get("result", [])

                # Check for payment ID in transactions
                for tx in transactions:
                    if await self._verify_transaction(tx, payment_id):
                        return True

                return False

        except Exception as e:
            logger.error(f"Payment check error: {e}")
            return False

    async def _verify_transaction(self, tx: Dict[str, Any], payment_id: str) -> bool:
        """Verify transaction contains payment ID"""
        try:
            if not tx.get("in_msg"):
                return False

            in_msg = tx["in_msg"]
            comment = str(in_msg.get("comment", ""))

            return payment_id in comment

        except Exception as e:
            logger.error(f"Transaction verification error: {e}")
            return False

    async def process_successful_payment(self, payment_id: str) -> bool:
        """Process successful payment and activate subscription"""
        try:
            async with aiosqlite.connect(Config.DB_PATH) as conn:
                # Get payment details
                cursor = await conn.execute("""
                                            SELECT user_id, subscription_type, ton_amount
                                            FROM payments
                                            WHERE id = ?
                                              AND status = 'pending'
                                            """, (payment_id,))

                payment = await cursor.fetchone()
                if not payment:
                    return False

                user_id, sub_type, amount = payment

                # Calculate subscription period
                now = datetime.now()
                if sub_type == "day":
                    expires = now + timedelta(days=1)
                elif sub_type == "week":
                    expires = now + timedelta(days=7)
                elif sub_type == "month":
                    expires = now + timedelta(days=30)
                elif sub_type == "year":
                    expires = now + timedelta(days=365)
                else:
                    return False

                # Update user subscription
                await conn.execute("""
                                   UPDATE users
                                   SET subscription_type    = ?,
                                       subscription_expires = ?
                                   WHERE user_id = ?
                                   """, (sub_type, expires.isoformat(), user_id))

                # Mark payment as completed
                await conn.execute("""
                                   UPDATE payments
                                   SET status       = 'completed',
                                       completed_at = ?
                                   WHERE id = ?
                                   """, (now.isoformat(), payment_id))

                await conn.commit()

                logger.info(f"Payment processed successfully: {payment_id}")
                return True

        except Exception as e:
            logger.error(f"Payment processing error: {e}")
            return False


# Protocol Configuration Generator
class ProtocolGenerator:

    async def generate_wireguard_config(self, server: ServerConfig, user_id: str) -> Dict[str, Any]:
        """Generate WireGuard configuration"""
        try:
            # Use banking port
            port = secrets.choice(server.banking_ports)

            # Generate keys
            private_key = subprocess.check_output(["wg", "genkey"]).decode().strip()
            public_key = subprocess.check_output(
                ["wg", "pubkey"], input=private_key.encode()
            ).decode().strip()

            client_ip = await self._get_next_ip(server.id, ProtocolType.WIREGUARD)

            # Get server public key
            server_public_key = subprocess.check_output(
                ["wg", "pubkey"], input=Config.WG_SERVER_PRIVATE_KEY.encode()
            ).decode().strip()

            config_data = {
                "private_key": private_key,
                "public_key": public_key,
                "client_ip": client_ip,
                "server_domain": server.domain,
                "server_port": port,
                "server_public_key": server_public_key,
                "port": port
            }

            # Generate client config
            client_config = f"""[Interface]
PrivateKey = {private_key}
Address = {client_ip}/24
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = {server_public_key}
Endpoint = {server.domain}:{port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""

            config_data["client_config"] = client_config
            return config_data

        except Exception as e:
            logger.error(f"WireGuard config generation failed: {e}")
            return None

    async def generate_shadowsocks_config(self, server: ServerConfig, user_id: str) -> Dict[str, Any]:
        """Generate ShadowSocks configuration"""
        try:
            async with aiosqlite.connect(Config.DB_PATH) as conn:
                cursor = await conn.execute("SELECT ss_password FROM users WHERE user_id = ?", (user_id,))
                row = await cursor.fetchone()

                if not row or not row[0]:
                    # Generate new password if not exists
                    password = base64.b64encode(secrets.token_bytes(16)).decode()
                    await conn.execute("UPDATE users SET ss_password = ? WHERE user_id = ?", (password, user_id))
                    await conn.commit()
                else:
                    password = row[0]

            method = "chacha20-ietf-poly1305"
            port = 8388

            # Register password through ss-manager
            await self._add_ss_password_on_server(password, port)

            auth = base64.b64encode(f"{method}:{password}".encode()).decode()
            ss_url = f"ss://{auth}@{server.domain}:{port}#SafeZoneHub"

            return {
                "server": server.domain,
                "server_port": port,
                "password": password,
                "method": method,
                "ss_url": ss_url,
                "port": port
            }

        except Exception as e:
            logger.error(f"ShadowSocks config generation failed: {e}")
            return None

    async def _add_ss_password_on_server(self, password: str, port: int):
        """Send JSON command to ss-manager"""
        data = json.dumps({
            "server_port": port,
            "password": password,
            "method": "chacha20-ietf-poly1305",
            "enable_udp": True
        }).encode()

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._send_ss_command, data)

    def _send_ss_command(self, data: bytes):
        """Send command to ss-manager with proper socket handling"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(data, ("127.0.0.1", 4000))
        except Exception as e:
            logger.error(f"Failed to send ss-manager command: {e}")

    async def generate_v2ray_config(self, server: ServerConfig, user_id: str) -> Dict[str, Any]:
        """Generate V2Ray configuration"""
        try:
            port = 443
            uuid_str = str(uuid.uuid4())

            # Client configuration
            client_config = {
                "outbounds": [{
                    "protocol": "vmess",
                    "settings": {
                        "vnext": [{
                            "address": server.domain,
                            "port": port,
                            "users": [{
                                "id": uuid_str,
                                "alterId": 0
                            }]
                        }]
                    },
                    "streamSettings": {
                        "network": "ws",
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": server.domain
                        },
                        "wsSettings": {
                            "path": f"/api/v1/users/{user_id}/ws",
                            "headers": {
                                "Host": server.domain
                            }
                        }
                    }
                }]
            }

            # Generate VMess URL
            vmess_config = {
                "v": "2",
                "ps": f"SafeZone-{server.location}",
                "add": server.domain,
                "port": port,
                "id": uuid_str,
                "aid": 0,
                "net": "ws",
                "type": "none",
                "host": server.domain,
                "path": f"/api/v1/users/{user_id}/ws",
                "tls": "tls"
            }

            vmess_url = f"vmess://{base64.b64encode(json.dumps(vmess_config).encode()).decode()}"

            config_data = {
                "uuid": uuid_str,
                "port": port,
                "client_config": client_config,
                "vmess_url": vmess_url
            }

            return config_data

        except Exception as e:
            logger.error(f"V2Ray config generation failed: {e}")
            return None

    async def generate_trojan_config(self, server: ServerConfig, user_id: str) -> Dict[str, Any]:
        """Generate Trojan configuration"""
        try:
            port = 443
            password = hashlib.sha224(f"{user_id}{secrets.token_hex(16)}".encode()).hexdigest()

            # Client configuration
            client_config = {
                "remote_addr": server.domain,
                "remote_port": port,
                "password": [password],
                "ssl": {
                    "verify": True,
                    "verify_hostname": True,
                    "sni": server.domain
                },
                "websocket": {
                    "enabled": True,
                    "path": f"/api/v1/users/{user_id}/stream",
                    "host": server.domain
                }
            }

            # Generate Trojan URL
            trojan_url = f"trojan://{password}@{server.domain}:{port}?type=ws&host={server.domain}&path=/api/v1/users/{user_id}/stream#{server.location}"

            config_data = {
                "password": password,
                "port": port,
                "client_config": client_config,
                "trojan_url": trojan_url
            }

            return config_data

        except Exception as e:
            logger.error(f"Trojan config generation failed: {e}")
            return None

    async def _get_next_ip(self, server_id: str, protocol: ProtocolType) -> str:
        """Get next available IP address"""
        async with aiosqlite.connect(Config.DB_PATH) as conn:
            cursor = await conn.execute("""
                                        SELECT config_data
                                        FROM configs
                                        WHERE protocol = ?
                                          AND server_id = ?
                                          AND is_active = TRUE
                                        """, (protocol.value, server_id))

            used_ips = set()
            async for row in cursor:
                try:
                    config = json.loads(row[0])
                    if 'client_ip' in config:
                        ip_parts = config['client_ip'].split('.')
                        if len(ip_parts) == 4:
                            used_ips.add(int(ip_parts[3]))
                except (json.JSONDecodeError, ValueError, IndexError):
                    continue

            # Find next available IP
            for i in range(10, 254):
                if i not in used_ips:
                    return f"10.66.66.{i}"

            raise Exception("No available IP addresses")


# Main VPN Bot Class
class SafeZoneBot:
    def __init__(self):
        self.db = DatabaseManager(Config.DB_PATH)
        self.payment_manager = TONPaymentManager(Config.TON_API_KEY, Config.TON_WALLET_ADDRESS)
        self.protocol_generator = ProtocolGenerator()
        self.rate_limiter = {}

    async def initialize(self):
        """Initialize bot components"""
        try:
            await self.db.init_database()
            await self.payment_manager.initialize()
            logger.info("SafeZone Bot initialized successfully")
        except Exception as e:
            logger.error(f"Bot initialization failed: {e}")
            raise

    def _check_rate_limit(self, user_id: str) -> bool:
        """Simple rate limiting"""
        now = time.time()
        user_requests = self.rate_limiter.get(user_id, [])

        # Remove old requests
        user_requests = [req_time for req_time in user_requests if now - req_time < 60]

        if len(user_requests) >= 10:  # 10 requests per minute
            return False

        user_requests.append(now)
        self.rate_limiter[user_id] = user_requests
        return True

    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Enhanced start command"""
        user = update.effective_user
        user_id = str(user.id)

        # Rate limiting
        if not self._check_rate_limit(user_id):
            await update.message.reply_text("⚠️ Слишком много запросов. Попробуйте через минуту.")
            return

        # Create or update user
        await self._create_or_update_user(user)

        # Get user status
        user_status = await self._get_user_status(user_id)
        subscription_info = await self._get_subscription_info(user_id)

        # Create menu
        keyboard = await self._create_main_menu(user_status, user_id)

        # Status text
        if user_status == UserStatus.ADMIN:
            status_text = "👑 Администратор"
        elif user_status == UserStatus.PREMIUM and subscription_info:
            days_left = subscription_info.get('days_left', 0)
            status_text = f"⭐ Premium ({days_left} дн.)"
        else:
            status_text = f"🆓 Бесплатный ({Config.FREE_DAILY_MINUTES} мин/день)"

        welcome_text = f"""🛡 **SafeZone Hub - Продвинутый VPN**

Добро пожаловать, {getattr(user, 'first_name', 'Пользователь')}! 

📊 **Статус:** {status_text}

🔒 **Доступные протоколы:**
• 🔑 **WireGuard** - быстрый и надёжный
• 🥷 **ShadowSocks** - обходит блокировки DPI
• 🚀 **V2Ray** - HTTPS маскировка
• 🛡 **Trojan** - максимальная скрытность

🏦 **Банковские порты:** 443, 465, 993, 8443
🔐 **Домен:** {Config.PRIMARY_DOMAIN}

Выберите действие:"""

        await update.message.reply_text(
            welcome_text,
            reply_markup=InlineKeyboardMarkup(keyboard),
            parse_mode='Markdown'
        )

    async def _create_main_menu(self, user_status: UserStatus, user_id: str) -> List[List[InlineKeyboardButton]]:
        """Create main menu based on user status"""
        keyboard = []

        if user_status in [UserStatus.ADMIN, UserStatus.PREMIUM]:
            keyboard.extend([
                [InlineKeyboardButton("🔑 WireGuard Pro", callback_data="create_wireguard_pro"),
                 InlineKeyboardButton("🥷 ShadowSocks", callback_data="create_shadowsocks")],
                [InlineKeyboardButton("🚀 V2Ray WebSocket", callback_data="create_v2ray_ws"),
                 InlineKeyboardButton("🛡 Trojan WS", callback_data="create_trojan_ws")]
            ])
        else:
            keyboard.extend([
                [InlineKeyboardButton("🔑 Пробный WG", callback_data="create_temp_wireguard"),
                 InlineKeyboardButton("🥷 Пробный SS", callback_data="create_temp_shadowsocks")],
                [InlineKeyboardButton("💎 Получить Premium", callback_data="show_pricing")]
            ])

        keyboard.extend([
            [InlineKeyboardButton("📋 Мои конфигурации", callback_data="my_configs"),
             InlineKeyboardButton("📊 Статистика", callback_data="user_stats")],
            [InlineKeyboardButton("🌐 Сервер", callback_data="server_info"),
             InlineKeyboardButton("❓ Помощь", callback_data="help_menu")],
            [InlineKeyboardButton("👥 Рефералы", callback_data="referral_program")]
        ])

        if user_status == UserStatus.ADMIN:
            keyboard.append([InlineKeyboardButton("⚙️ Админ панель", callback_data="admin_panel")])

        return keyboard

    async def _create_or_update_user(self, tg_user):
        """Create or update user record"""
        user_id = str(tg_user.id)
        username = tg_user.username or ""
        first_name = getattr(tg_user, "first_name", "") or ""
        last_name = getattr(tg_user, "last_name", "") or ""
        language_code = getattr(tg_user, "language_code", "ru") or "ru"
        now_iso = datetime.utcnow().isoformat()

        async with aiosqlite.connect(Config.DB_PATH) as conn:
            await conn.execute("PRAGMA foreign_keys = ON")

            # Generate unique ss_password and referral_code for new users
            ss_password = base64.b64encode(secrets.token_bytes(16)).decode()
            ref_code = f"REF{secrets.token_hex(4).upper()}"

            # Try to insert new user (will be ignored if exists)
            await conn.execute("""
                               INSERT
                               OR IGNORE INTO users
                (user_id, username, first_name, last_name, language_code, 
                 last_activity, ss_password, referral_code)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                               """, (user_id, username, first_name, last_name,
                                     language_code, now_iso, ss_password, ref_code))

            # Fill ss_password for existing users who don't have it
            await conn.execute("""
                               UPDATE users
                               SET ss_password = ?
                               WHERE user_id = ?
                                 AND ss_password IS NULL
                               """, (ss_password, user_id))

            # Always update changeable data
            await conn.execute("""
                               UPDATE users
                               SET username      = ?,
                                   first_name    = ?,
                                   last_name     = ?,
                                   language_code = ?,
                                   last_activity = ?
                               WHERE user_id = ?
                               """, (username, first_name, last_name, language_code, now_iso, user_id))

            await conn.commit()

    async def _get_user_status(self, user_id: str) -> UserStatus:
        """Get user status"""
        if int(user_id) in Config.ADMIN_IDS:
            return UserStatus.ADMIN

        async with aiosqlite.connect(Config.DB_PATH) as conn:
            cursor = await conn.execute("""
                                        SELECT subscription_expires
                                        FROM users
                                        WHERE user_id = ?
                                        """, (user_id,))

            result = await cursor.fetchone()
            if not result or not result[0]:
                return UserStatus.FREE

            expires = datetime.fromisoformat(result[0])
            if datetime.now() < expires:
                return UserStatus.PREMIUM
            else:
                return UserStatus.FREE

    async def _get_subscription_info(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get subscription information"""
        async with aiosqlite.connect(Config.DB_PATH) as conn:
            cursor = await conn.execute("""
                                        SELECT subscription_type, subscription_expires
                                        FROM users
                                        WHERE user_id = ?
                                        """, (user_id,))

            result = await cursor.fetchone()
            if not result or not result[1]:
                return None

            expires = datetime.fromisoformat(result[1])
            days_left = (expires - datetime.now()).days

            return {
                "type": result[0] or "unknown",
                "expires_at": expires,
                "days_left": max(0, days_left),
                "active": datetime.now() < expires
            }

    # Protocol creation handlers
    async def create_protocol_config(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Universal protocol configuration handler"""
        query = update.callback_query
        await query.answer()

        user_id = str(query.from_user.id)
        callback_data = query.data

        # Rate limiting
        if not self._check_rate_limit(user_id):
            await query.edit_message_text("⚠️ Слишком много запросов.")
            return

        # Parse protocol - updated protocol_map with correct button names
        protocol_map = {
            "create_wireguard_pro": (ProtocolType.WIREGUARD, False),
            "create_temp_wireguard": (ProtocolType.WIREGUARD, True),
            "create_shadowsocks": (ProtocolType.SHADOWSOCKS, False),
            "create_temp_shadowsocks": (ProtocolType.SHADOWSOCKS, True),
            "create_v2ray_ws": (ProtocolType.V2RAY, False),
            "create_trojan_ws": (ProtocolType.TROJAN, False)
        }

        config_info = protocol_map.get(callback_data)
        if not config_info:
            await query.edit_message_text("❌ Неизвестный протокол")
            return

        protocol, is_temporary = config_info

        # Check permissions
        user_status = await self._get_user_status(user_id)
        can_create, error_msg = await self._check_creation_permissions(user_id, user_status, is_temporary)

        if not can_create:
            await query.edit_message_text(f"❌ {error_msg}")
            return

        # Create configuration
        await self._create_and_deploy_config(query, protocol, is_temporary, context)

    async def _check_creation_permissions(self, user_id: str, user_status: UserStatus,
                                          is_temporary: bool) -> Tuple[bool, Optional[str]]:
        """Check if user can create configuration"""
        if user_status in [UserStatus.ADMIN, UserStatus.PREMIUM]:
            return True, None

        if not is_temporary:
            return False, "💎 Постоянные конфигурации доступны только Premium пользователям!"

        # Check daily usage for free users
        async with aiosqlite.connect(Config.DB_PATH) as conn:
            cursor = await conn.execute("""
                                        SELECT daily_usage, last_usage_date
                                        FROM users
                                        WHERE user_id = ?
                                        """, (user_id,))

            result = await cursor.fetchone()
            if not result:
                return True, None

            today = datetime.now().date()
            # Fix for null last_usage_date
            if result[1]:
                last_usage_date = datetime.fromisoformat(result[1]).date()
                daily_usage = result[0] if last_usage_date == today else 0
            else:
                daily_usage = 0

            if daily_usage >= Config.FREE_DAILY_MINUTES:
                return False, f"🕐 Дневной лимит исчерпан ({Config.FREE_DAILY_MINUTES} мин)."

        return True, None

    async def _create_and_deploy_config(self, query, protocol: ProtocolType,
                                        is_temporary: bool, context: ContextTypes.DEFAULT_TYPE):
        """Create and deploy protocol configuration"""
        user_id = str(query.from_user.id)
        server = Config.SERVERS[0]  # Use primary server

        try:
            # Show progress
            await query.edit_message_text(f"⏳ Создание {protocol.value.title()} конфигурации...")

            # Generate configuration
            config_generators = {
                ProtocolType.WIREGUARD: self.protocol_generator.generate_wireguard_config,
                ProtocolType.SHADOWSOCKS: self.protocol_generator.generate_shadowsocks_config,
                ProtocolType.V2RAY: self.protocol_generator.generate_v2ray_config,
                ProtocolType.TROJAN: self.protocol_generator.generate_trojan_config
            }

            config_data = await config_generators[protocol](server, user_id)

            if not config_data:
                await query.edit_message_text("❌ Не удалось создать конфигурацию")
                return

            # Determine expiration
            user_status = await self._get_user_status(user_id)
            if is_temporary or user_status == UserStatus.FREE:
                expires_at = datetime.now() + timedelta(minutes=Config.TEMP_CONFIG_LIFETIME)
                await self._update_user_usage(user_id, Config.TEMP_CONFIG_LIFETIME)
                lifetime_text = f"⏰ {Config.TEMP_CONFIG_LIFETIME} минут"
            else:
                expires_at = None
                lifetime_text = "♾️ Постоянная"

            # Save to database
            config_id = await self._save_config_to_db(
                user_id, protocol, server.id, config_data, expires_at
            )

            # Send configuration to user
            await self._send_config_to_user(
                query.message.chat_id, protocol, config_data, server,
                expires_at, lifetime_text, context
            )

            # Schedule cleanup for temporary configs
            if expires_at:
                context.job_queue.run_once(
                    self._cleanup_expired_config,
                    when=Config.TEMP_CONFIG_LIFETIME * 60,
                    data={
                        "config_id": config_id,
                        "user_id": user_id,
                        "protocol": protocol.value,
                        "config_data": config_data
                    }
                )

            success_text = f"✅ **{protocol.value.title()} конфигурация создана!**\n\n⏱️ **Тип:** {lifetime_text}"
            await query.edit_message_text(success_text, parse_mode='Markdown')

        except Exception as e:
            logger.error(f"Config creation failed: {e}")
            await query.edit_message_text(f"❌ Ошибка: {str(e)}")

    async def _save_config_to_db(self, user_id: str, protocol: ProtocolType,
                                 server_id: str, config_data: Dict[str, Any],
                                 expires_at: Optional[datetime]) -> int:
        """Save configuration to database with safe column handling"""
        async with aiosqlite.connect(Config.DB_PATH) as conn:
            # Try to insert with all columns first
            try:
                cursor = await conn.execute("""
                                            INSERT INTO configs
                                            (user_id, protocol, server_id, config_data, port, expires_at, created_at)
                                            VALUES (?, ?, ?, ?, ?, ?, ?)
                                            """, (
                                                user_id, protocol.value, server_id, json.dumps(config_data),
                                                config_data.get('port', 443),
                                                expires_at.isoformat() if expires_at else None,
                                                datetime.now().isoformat()
                                            ))

                config_id = cursor.lastrowid
                await conn.commit()
                return config_id

            except Exception as e:
                logger.warning(f"Full config insert failed: {e}")
                # Fallback to minimal insert without port column
                try:
                    cursor = await conn.execute("""
                                                INSERT INTO configs
                                                    (user_id, protocol, server_id, config_data, expires_at, created_at)
                                                VALUES (?, ?, ?, ?, ?, ?)
                                                """, (
                                                    user_id, protocol.value, server_id, json.dumps(config_data),
                                                    expires_at.isoformat() if expires_at else None,
                                                    datetime.now().isoformat()
                                                ))

                    config_id = cursor.lastrowid
                    await conn.commit()
                    return config_id

                except Exception as e2:
                    logger.error(f"Minimal config insert also failed: {e2}")
                    return 0

    async def _send_config_to_user(self, chat_id: int, protocol: ProtocolType,
                                   config_data: Dict[str, Any], server: ServerConfig,
                                   expires_at: Optional[datetime], lifetime_text: str,
                                   context: ContextTypes.DEFAULT_TYPE):
        """Send configuration to user"""
        try:
            if protocol == ProtocolType.WIREGUARD:
                await self._send_wireguard_config(chat_id, config_data, server, expires_at, lifetime_text, context)
            elif protocol == ProtocolType.SHADOWSOCKS:
                await self._send_shadowsocks_config(chat_id, config_data, server, expires_at, lifetime_text, context)
            elif protocol == ProtocolType.V2RAY:
                await self._send_v2ray_config(chat_id, config_data, server, expires_at, lifetime_text, context)
            elif protocol == ProtocolType.TROJAN:
                await self._send_trojan_config(chat_id, config_data, server, expires_at, lifetime_text, context)

        except Exception as e:
            logger.error(f"Failed to send {protocol.value} config: {e}")

    async def _send_wireguard_config(self, chat_id: int, config_data: Dict[str, Any],
                                     server: ServerConfig, expires_at: Optional[datetime],
                                     lifetime_text: str, context: ContextTypes.DEFAULT_TYPE):
        """Send WireGuard configuration"""
        client_config = config_data["client_config"]

        # Create QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(client_config)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as qr_file:
            img.save(qr_file.name)
            qr_path = qr_file.name

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".conf") as conf_file:
            conf_file.write(client_config)
            conf_path = conf_file.name

        config_info = f"""🔑 **WireGuard Pro Configuration**

🌐 **Сервер:** {server.name}
📍 **Локация:** {server.location}
🏦 **Банковский порт:** {config_data['server_port']}
📱 **Ваш IP:** `{config_data['client_ip']}`
⏱️ **Тип:** {lifetime_text}
📅 **Создана:** {datetime.now().strftime('%Y-%m-%d %H:%M')}

📱 **Подключение:**
1. Скачайте WireGuard
2. Отсканируйте QR код или импортируйте файл
3. Активируйте подключение"""

        if expires_at:
            config_info += f"\n\n⚠️ **Истекает:** {expires_at.strftime('%Y-%m-%d %H:%M')}"

        await context.bot.send_message(chat_id=chat_id, text=config_info, parse_mode='Markdown')

        # Send files
        with open(conf_path, 'rb') as conf:
            await context.bot.send_document(
                chat_id=chat_id,
                document=conf,
                filename=f"SafeZone_WG_{server.location}.conf"
            )

        with open(qr_path, 'rb') as qr:
            await context.bot.send_photo(
                chat_id=chat_id,
                photo=qr,
                caption="📱 QR код для подключения"
            )

        # Cleanup
        os.unlink(conf_path)
        os.unlink(qr_path)

    async def _send_shadowsocks_config(self, chat_id: int, config_data: Dict[str, Any],
                                       server: ServerConfig, expires_at: Optional[datetime],
                                       lifetime_text: str, context: ContextTypes.DEFAULT_TYPE):
        """Send ShadowSocks configuration"""
        ss_url = config_data["ss_url"]

        # QR-код
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(ss_url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as qr_file:
            img.save(qr_file.name)
            qr_path = qr_file.name

        # Текстовый файл-шпаргалка
        config_text = (
            f"ShadowSocks configuration\n\n"
            f"Server:   {config_data['server']}\n"
            f"Port:     {config_data['server_port']}\n"
            f"Method:   {config_data['method']}\n"
            f"Password: {config_data['password']}\n\n"
            f"SS URL:   {ss_url}\n"
        )
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".txt") as conf_file:
            conf_file.write(config_text)
            conf_path = conf_file.name

        # Сообщение в чат
        msg = (
            f"🥷 **ShadowSocks Configuration**\n\n"
            f"🌐 **Сервер:** {server.name}\n"
            f"🔑 **Метод:** `{config_data['method']}`\n"
            f"📦 **Порт:** `{config_data['server_port']}`\n"
            f"⏱️ **Тип:** {lifetime_text}\n\n"
            f"🔗 **SS URL:**\n`{ss_url}`"
        )
        if expires_at:
            msg += f"\n\n⚠️ **Истекает:** {expires_at.strftime('%Y-%m-%d %H:%M')}"

        await context.bot.send_message(chat_id, msg, parse_mode="Markdown")

        # отправляем файлик и QR-код
        with open(conf_path, "rb") as f:
            await context.bot.send_document(chat_id, f, filename="shadowsocks_config.txt")
        with open(qr_path, "rb") as f:
            await context.bot.send_photo(chat_id, f, caption="📱 QR-код для быстрого импорта")

        # clean-up
        os.unlink(conf_path)
        os.unlink(qr_path)

    async def _send_v2ray_config(self, chat_id: int, config_data: Dict[str, Any],
                                 server: ServerConfig, expires_at: Optional[datetime],
                                 lifetime_text: str, context: ContextTypes.DEFAULT_TYPE):
        """Send V2Ray configuration"""
        vmess_url = config_data["vmess_url"]

        # Create QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(vmess_url)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as qr_file:
            img.save(qr_file.name)
            qr_path = qr_file.name

        config_json = json.dumps(config_data["client_config"], indent=2)

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".json") as conf_file:
            conf_file.write(config_json)
            conf_path = conf_file.name

        config_info = f"""🚀 **V2Ray WebSocket Configuration**

🌐 **Сервер:** {server.name}
🏦 **HTTPS порт:** {config_data['port']}
🔐 **UUID:** `{config_data['uuid'][:16]}...`
🔒 **Обфускация:** WebSocket + TLS
⏱️ **Тип:** {lifetime_text}

🔗 **VMess URL:**\n`{vmess_url}`"""

        if expires_at:
            config_info += f"\n\n⚠️ **Истекает:** {expires_at.strftime('%Y-%m-%d %H:%M')}"

        await context.bot.send_message(chat_id=chat_id, text=config_info, parse_mode='Markdown')

        with open(conf_path, 'rb') as conf:
            await context.bot.send_document(
                chat_id=chat_id,
                document=conf,
                filename="v2ray_config.json"
            )

        with open(qr_path, 'rb') as qr:
            await context.bot.send_photo(
                chat_id=chat_id,
                photo=qr,
                caption="📱 QR код для подключения"
            )

        os.unlink(conf_path)
        os.unlink(qr_path)

    async def _send_trojan_config(self, chat_id: int, config_data: Dict[str, Any],
                                  server: ServerConfig, expires_at: Optional[datetime],
                                  lifetime_text: str, context: ContextTypes.DEFAULT_TYPE):
        """Send Trojan configuration"""
        trojan_url = config_data["trojan_url"]

        # Create QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(trojan_url)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as qr_file:
            img.save(qr_file.name)
            qr_path = qr_file.name

        config_json = json.dumps(config_data["client_config"], indent=2)

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".json") as conf_file:
            conf_file.write(config_json)
            conf_path = conf_file.name

        config_info = f"""🛡 **Trojan WebSocket Configuration**

🌐 **Сервер:** {server.name}
🏦 **HTTPS порт:** {config_data['port']}
🔐 **Пароль:** `{config_data['password'][:16]}...`
🔒 **Обфускация:** WebSocket + TLS
⏱️ **Тип:** {lifetime_text}

🔗 **Trojan URL:**\n`{trojan_url}`"""

        if expires_at:
            config_info += f"\n\n⚠️ **Истекает:** {expires_at.strftime('%Y-%m-%d %H:%M')}"

        await context.bot.send_message(chat_id=chat_id, text=config_info, parse_mode='Markdown')

        with open(conf_path, 'rb') as conf:
            await context.bot.send_document(
                chat_id=chat_id,
                document=conf,
                filename="trojan_config.json"
            )

        with open(qr_path, 'rb') as qr:
            await context.bot.send_photo(
                chat_id=chat_id,
                photo=qr,
                caption="📱 QR код для подключения"
            )

        os.unlink(conf_path)
        os.unlink(qr_path)

    async def _update_user_usage(self, user_id: str, minutes: int):
        """Update user daily usage"""
        async with aiosqlite.connect(Config.DB_PATH) as conn:
            today = datetime.now().date().isoformat()
            await conn.execute("""
                               UPDATE users
                               SET daily_usage     = CASE
                                                         WHEN last_usage_date = ? THEN daily_usage + ?
                                                         ELSE ?
                                   END,
                                   last_usage_date = ?
                               WHERE user_id = ?
                               """, (today, minutes, minutes, today, user_id))
            await conn.commit()

    async def _cleanup_expired_config(self, context: ContextTypes.DEFAULT_TYPE):
        """Clean up expired configuration"""
        job_data = context.job.data
        config_id = job_data["config_id"]
        user_id = job_data["user_id"]

        try:
            # Mark as inactive in database
            async with aiosqlite.connect(Config.DB_PATH) as conn:
                await conn.execute("""
                                   UPDATE configs
                                   SET is_active = FALSE
                                   WHERE id = ?
                                   """, (config_id,))
                await conn.commit()

            # Notify user
            await context.bot.send_message(
                chat_id=user_id,
                text="⏰ **Временная конфигурация истекла**\n\n💎 Купите Premium для постоянного доступа!",
                parse_mode='Markdown'
            )

            logger.info(f"Cleaned up expired config {config_id} for user {user_id}")

        except Exception as e:
            logger.error(f"Config cleanup failed: {e}")

    # Payment handlers
    async def show_pricing(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show pricing information"""
        query = update.callback_query
        await query.answer()

        pricing_text = f"""💎 **SafeZone Hub Premium**

🎯 **Специальные цены для России**

📅 **Тарифы:**

**День** - {Config.PRICES['day'].ton} TON ({Config.PRICES['day'].rub} ₽)
• 24 часа безлимитного доступа

**Неделя** - {Config.PRICES['week'].ton} TON ({Config.PRICES['week'].rub} ₽)
• Скидка 40% от дневной цены

**Месяц** - {Config.PRICES['month'].ton} TON ({Config.PRICES['month'].rub} ₽)
• Скидка 67% - популярный выбор

**Год** - {Config.PRICES['year'].ton} TON ({Config.PRICES['year'].rub} ₽)
• Скидка 75% - максимальная выгода

⭐ **Premium преимущества:**
• Все протоколы с продвинутой обфускацией
• Банковские порты для максимального обхода
• Неограниченные конфигурации
• Приоритетная поддержка

🔒 **Оплата через TON Blockchain**"""

        keyboard = [
            [InlineKeyboardButton(f"📅 День - {Config.PRICES['day'].ton} TON", callback_data="buy_day")],
            [InlineKeyboardButton(f"📅 Неделя - {Config.PRICES['week'].ton} TON", callback_data="buy_week")],
            [InlineKeyboardButton(f"📅 Месяц - {Config.PRICES['month'].ton} TON", callback_data="buy_month")],
            [InlineKeyboardButton(f"📅 Год - {Config.PRICES['year'].ton} TON", callback_data="buy_year")],
            [InlineKeyboardButton("💰 Как купить TON?", callback_data="how_to_buy_ton")],
            [InlineKeyboardButton("🔙 Назад", callback_data="back_to_menu")]
        ]

        await query.edit_message_text(
            pricing_text,
            reply_markup=InlineKeyboardMarkup(keyboard),
            parse_mode='Markdown'
        )

    async def process_payment(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Process payment request"""
        query = update.callback_query
        await query.answer()

        user_id = str(query.from_user.id)
        subscription_type = query.data.replace("buy_", "")

        if subscription_type not in Config.PRICES:
            await query.edit_message_text("❌ Неизвестный тариф")
            return

        price = Config.PRICES[subscription_type]

        # Create payment request
        payment_request = await self.payment_manager.create_payment_request(
            user_id, price.ton, subscription_type
        )

        # Create QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(payment_request["ton_url"])
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as qr_file:
            img.save(qr_file.name)
            qr_path = qr_file.name

        payment_text = f"""💳 **Оплата Premium - {subscription_type.title()}**

💰 **Сумма:** {price.ton} TON (~{price.rub} ₽)
🏦 **Кошелек:** `{payment_request['wallet_address']}`
📝 **Комментарий:** `{payment_request['comment']}`

⚠️ **ВАЖНО:** Обязательно укажите комментарий!

🔗 **Быстрые ссылки:**
• [Tonkeeper]({payment_request['tonkeeper_url']})
• [TON Wallet]({payment_request['ton_url']})

💡 **Как оплатить:**
1. Отсканируйте QR код кошельком
2. Проверьте сумму и комментарий
3. Подтвердите транзакцию
4. Нажмите "Проверить платеж"
"""

        keyboard = [
            [InlineKeyboardButton("🔍 Проверить платеж",
                                  callback_data=f"check_payment_{payment_request['payment_id']}")],
            [InlineKeyboardButton("❓ Помощь с оплатой", callback_data="payment_help")],
            [InlineKeyboardButton("🔙 К тарифам", callback_data="show_pricing")]
        ]

        await query.edit_message_text(
            payment_text,
            reply_markup=InlineKeyboardMarkup(keyboard),
            parse_mode='Markdown',
            disable_web_page_preview=True
        )

        # Send QR code
        with open(qr_path, 'rb') as qr:
            await context.bot.send_photo(
                chat_id=query.message.chat_id,
                photo=qr,
                caption=f"📱 QR код для оплаты {price.ton} TON"
            )

        os.unlink(qr_path)

    async def check_payment(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Check payment status"""
        query = update.callback_query
        await query.answer()

        payment_id = query.data.replace("check_payment_", "")

        await query.edit_message_text("🔄 Проверяем платеж...")

        # Check payment status
        is_paid = await self.payment_manager.check_payment_status(payment_id)

        if is_paid:
            success = await self.payment_manager.process_successful_payment(payment_id)

            if success:
                await query.edit_message_text("""✅ **Платеж получен!**

🎉 **Подписка активирована!**
⭐ Теперь у вас есть доступ ко всем протоколам.

Возвращайтесь в главное меню для создания конфигураций.""",
                                              reply_markup=InlineKeyboardMarkup([
                                                  [InlineKeyboardButton("🏠 Главное меню", callback_data="back_to_menu")]
                                              ]), parse_mode='Markdown')
            else:
                await query.edit_message_text("❌ Ошибка активации подписки. Обратитесь в поддержку.")
        else:
            keyboard = [
                [InlineKeyboardButton("🔍 Проверить еще раз", callback_data=f"check_payment_{payment_id}")],
                [InlineKeyboardButton("❓ Помощь", callback_data="payment_help")],
                [InlineKeyboardButton("🔙 К тарифам", callback_data="show_pricing")]
            ]

            await query.edit_message_text(
                """❌ **Платеж не найден**

⏰ Подождите 2-3 минуты и попробуйте еще раз

💡 **Проверьте:**
• Сумма: точно как указано
• Комментарий: скопирован полностью
• Адрес: правильный кошелек""",
                reply_markup=InlineKeyboardMarkup(keyboard),
                parse_mode='Markdown'
            )

    # Menu handlers
    async def back_to_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Return to main menu"""
        query = update.callback_query
        await query.answer()

        # Simulate message for start command
        class FakeMessage:
            def __init__(self, chat_id):
                self.chat_id = chat_id

            async def reply_text(self, text, reply_markup=None, parse_mode=None):
                await context.bot.send_message(
                    chat_id=self.chat_id,
                    text=text,
                    reply_markup=reply_markup,
                    parse_mode=parse_mode
                )

        fake_update = type('obj', (object,), {
            'effective_user': query.from_user,
            'message': FakeMessage(query.message.chat_id)
        })

        await self.start_command(fake_update, context)

    # Additional menu handlers
    async def my_configs(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show user configurations with safe column handling"""
        query = update.callback_query
        await query.answer()

        user_id = str(query.from_user.id)

        async with aiosqlite.connect(Config.DB_PATH) as conn:
            # Try to get configs with port column first
            try:
                cursor = await conn.execute("""
                                            SELECT protocol, port, created_at, expires_at, is_active
                                            FROM configs
                                            WHERE user_id = ?
                                            ORDER BY created_at DESC LIMIT 10
                                            """, (user_id,))

                configs = await cursor.fetchall()
                has_port_column = True

            except Exception as e:
                logger.warning(f"Query with port failed: {e}")
                # Fallback to query without port column
                try:
                    cursor = await conn.execute("""
                                                SELECT protocol, 443 as port, created_at, expires_at, is_active
                                                FROM configs
                                                WHERE user_id = ?
                                                ORDER BY created_at DESC LIMIT 10
                                                """, (user_id,))

                    configs = await cursor.fetchall()
                    has_port_column = False

                except Exception as e2:
                    logger.error(f"Fallback query also failed: {e2}")
                    configs = []
                    has_port_column = False

        if not configs:
            config_text = "📋 **Мои конфигурации**\n\nУ вас пока нет конфигураций."
        else:
            config_text = "📋 **Мои конфигурации**\n\n"

            for protocol, port, created_at, expires_at, is_active in configs:
                created = datetime.fromisoformat(created_at)

                if not is_active:
                    status = "🔴 Неактивна"
                elif expires_at:
                    expires = datetime.fromisoformat(expires_at)
                    if datetime.now() > expires:
                        status = "⏰ Истекла"
                    else:
                        status = "🟢 Активна"
                else:
                    status = "🟢 Постоянная"

                port_text = f" (порт {port})" if has_port_column and port else ""
                config_text += f"• **{protocol.title()}**{port_text} - {status}\n"
                config_text += f"  Создана: {created.strftime('%d.%m %H:%M')}\n\n"

        keyboard = [[InlineKeyboardButton("🔙 Назад", callback_data="back_to_menu")]]

        await query.edit_message_text(
            config_text,
            reply_markup=InlineKeyboardMarkup(keyboard),
            parse_mode='Markdown'
        )

    async def help_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show help menu"""
        query = update.callback_query
        await query.answer()

        help_text = """❓ **Справка SafeZone Hub**

🔒 **Протоколы:**

🔑 **WireGuard** - самый быстрый
🥷 **ShadowSocks** - обходит DPI
🚀 **V2Ray** - HTTPS маскировка  
🛡 **Trojan** - максимальная скрытность

📱 **Приложения:**

**Android:**
• v2rayNG (все протоколы)
• WireGuard
• Shadowsocks

**iOS:**
• Shadowrocket (платно)
• WireGuard (бесплатно)

**Windows:**
• v2rayN (все протоколы)
• WireGuard

💡 **Советы:**
• При блокировках пробуйте разные протоколы
• Trojan лучше всего обходит DPI
• Используйте конфигурации сразу после создания

🏦 **Банковские порты:** 443, 465, 993, 8443
🔐 **Обфускация:** TLS, WebSocket для обхода DPI"""

        keyboard = [[InlineKeyboardButton("🔙 Назад", callback_data="back_to_menu")]]

        await query.edit_message_text(
            help_text,
            reply_markup=InlineKeyboardMarkup(keyboard),
            parse_mode='Markdown'
        )

    async def user_stats(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show user statistics"""
        query = update.callback_query
        await query.answer()

        user_id = str(query.from_user.id)

        async with aiosqlite.connect(Config.DB_PATH) as conn:
            # Get user info
            cursor = await conn.execute("""
                                        SELECT created_at, daily_usage, total_usage_bytes, referral_earnings
                                        FROM users
                                        WHERE user_id = ?
                                        """, (user_id,))
            user_info = await cursor.fetchone()

            # Get config count
            cursor = await conn.execute("""
                                        SELECT COUNT(*)
                                        FROM configs
                                        WHERE user_id = ?
                                        """, (user_id,))
            config_count = await cursor.fetchone()[0]

            # Get active configs
            cursor = await conn.execute("""
                                        SELECT COUNT(*)
                                        FROM configs
                                        WHERE user_id = ?
                                          AND is_active = TRUE
                                        """, (user_id,))
            active_configs = await cursor.fetchone()[0]

        if user_info:
            created_at, daily_usage, total_usage_bytes, referral_earnings = user_info
            created = datetime.fromisoformat(created_at)

            stats_text = f"""📊 **Ваша статистика**

👤 **Аккаунт:**
• Регистрация: {created.strftime('%d.%m.%Y')}
• Дней с нами: {(datetime.now() - created).days}

📈 **Использование:**
• Сегодня: {daily_usage} мин
• Всего трафика: {total_usage_bytes / (1024 * 1024):.1f} МБ
• Конфигураций создано: {config_count}
• Активных конфигураций: {active_configs}

💰 **Рефералы:**
• Заработано: {referral_earnings:.2f} TON"""
        else:
            stats_text = "📊 **Статистика недоступна**"

        keyboard = [[InlineKeyboardButton("🔙 Назад", callback_data="back_to_menu")]]

        await query.edit_message_text(
            stats_text,
            reply_markup=InlineKeyboardMarkup(keyboard),
            parse_mode='Markdown'
        )

    async def server_info(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show server information"""
        query = update.callback_query
        await query.answer()

        server = Config.SERVERS[0]  # Primary server

        server_text = f"""🌐 **Информация о сервере**

**{server.name}**
📍 **Локация:** {server.location}
🌐 **Домен:** `{server.domain}`
👥 **Макс. пользователей:** {server.max_users}

🏦 **Банковские порты:**
• 443 (HTTPS) - основной
• 465 (SMTP SSL) - email
• 993 (IMAP SSL) - email  
• 8443 (Alt HTTPS) - альтернативный
• 1521 (Oracle) - база данных

🔒 **Особенности:**
• SSL сертификаты
• Автоматическое обновление
• DPI обход через банковские порты
• Продвинутая обфускация трафика

📊 **Статус:** 🟢 Онлайн
⚡ **Нагрузка:** Низкая
🔄 **Время работы:** 99.9%

💡 **Рекомендации:**
• Trojan наиболее скрытный для DPI
• V2Ray отлично работает с WebSocket
• WireGuard самый быстрый протокол
• ShadowSocks стабильно обходит блокировки"""

        keyboard = [[InlineKeyboardButton("🔙 Назад", callback_data="back_to_menu")]]

        await query.edit_message_text(
            server_text,
            reply_markup=InlineKeyboardMarkup(keyboard),
            parse_mode='Markdown'
        )

    async def referral_program(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show referral program"""
        query = update.callback_query
        await query.answer()

        user_id = str(query.from_user.id)

        async with aiosqlite.connect(Config.DB_PATH) as conn:
            cursor = await conn.execute(
                "SELECT referral_code, referral_earnings FROM users WHERE user_id = ?",
                (user_id,)
            )
            result = await cursor.fetchone()

            if result:
                referral_code, earnings = result
            else:
                referral_code, earnings = "UNKNOWN", 0.0

            # Count referrals
            cursor = await conn.execute(
                "SELECT COUNT(*) FROM users WHERE referred_by = ?",
                (referral_code,)
            )
            referral_count = await cursor.fetchone()[0]

        bot_username = context.bot.username or "SafeZoneHubBot"
        referral_text = f"""👥 **Реферальная программа**

🎯 **Ваш код:** `{referral_code}`

📊 **Статистика:**
• Приглашено: {referral_count} человек
• Заработано: {earnings:.2f} TON

💰 **Как работает:**
• Поделитесь кодом с друзьями
• За каждого активного реферала получите 10% от его платежей
• Бонусы начисляются автоматически

🔗 **Ссылка для друзей:**
`https://t.me/{bot_username}?start={referral_code}`

📝 **Активировать чужой код:**
Отправьте: `/ref КОД`

🎁 **Бонусы:**
• День → 0.03 TON
• Неделя → 0.15 TON  
• Месяц → 0.5 TON
• Год → 4 TON + бонус месяц"""

        keyboard = [[InlineKeyboardButton("🔙 Назад", callback_data="back_to_menu")]]

        await query.edit_message_text(
            referral_text,
            reply_markup=InlineKeyboardMarkup(keyboard),
            parse_mode='Markdown'
        )

    async def payment_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show payment help"""
        query = update.callback_query
        await query.answer()

        help_text = """❓ **Помощь с оплатой TON**

📱 **Как купить TON:**

**1. Установите кошелек:**
• [Tonkeeper](https://tonkeeper.com/) - рекомендуем
• [TON Wallet](https://wallet.ton.org/) - официальный
• @wallet - в Telegram

**2. Купите TON:**
• Внутри Tonkeeper (карта/Apple Pay)
• Обменники: @xchangebot, @CryptoBot
• Биржи: Binance, OKX, Bybit

**3. Отправьте платеж:**
• Отсканируйте QR код
• **ОБЯЗАТЕЛЬНО** укажите комментарий
• Проверьте сумму и адрес
• Подтвердите транзакцию

🔧 **Проблемы:**

**Платеж не находится:**
• Подождите 2-3 минуты
• Проверьте комментарий
• Убедитесь в правильности суммы

**Ошибка отправки:**
• Проверьте баланс TON
• Перезапустите кошелек
• Проверьте интернет

💰 **Курс TON:**
• 1 TON ≈ 60-70 ₽
• Месяц Premium = 5 TON ≈ 300-350 ₽

🆘 **Поддержка:**
• Telegram: @safezonehub_support
• Отвечаем в течение 1 часа"""

        keyboard = [
            [InlineKeyboardButton("📱 Скачать Tonkeeper", url="https://tonkeeper.com/")],
            [InlineKeyboardButton("🔙 К оплате", callback_data="show_pricing")]
        ]

        await query.edit_message_text(
            help_text,
            reply_markup=InlineKeyboardMarkup(keyboard),
            parse_mode='Markdown',
            disable_web_page_preview=True
        )

    async def how_to_buy_ton(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """How to buy TON guide"""
        query = update.callback_query
        await query.answer()

        guide_text = """💰 **Как купить TON**

🎯 **Самые простые способы:**

**1. Tonkeeper (рекомендуем):**
• Скачайте приложение
• Создайте кошелек
• Нажмите "Купить TON"
• Оплатите картой или Apple Pay

**2. Telegram @wallet:**
• Откройте @wallet в Telegram
• Создайте кошелек
• Купите TON через меню

**3. Обменники:**
• @xchangebot - в Telegram
• @CryptoBot - удобно
• Garantex - P2P обмен

**4. Биржи:**
• Binance (самая популярная)
• OKX
• Bybit

💡 **Советы:**
• Начните с Tonkeeper - проще всего
• P2P обмен часто выгоднее
• Внутри Tonkeeper удобно, но комиссия выше
• Биржи подходят для больших сумм

⚡ **Быстрая покупка:**
1. Установите Tonkeeper
2. Нажмите "Купить TON"
3. Выберите сумму
4. Оплатите картой
5. Сразу отправляйте на наш кошелек

🔒 **Безопасность:**
• Используйте только официальные приложения
• Проверяйте адреса кошельков
• Сохраните seed-фразу кошелька"""

        keyboard = [
            [InlineKeyboardButton("📱 Скачать Tonkeeper", url="https://tonkeeper.com/")],
            [InlineKeyboardButton("🤖 Открыть @wallet", url="https://t.me/wallet")],
            [InlineKeyboardButton("🔙 К тарифам", callback_data="show_pricing")]
        ]

        await query.edit_message_text(
            guide_text,
            reply_markup=InlineKeyboardMarkup(keyboard),
            parse_mode='Markdown'
        )


def main():
    """Main function to run the bot"""
    try:
        # Initialize bot
        bot = SafeZoneBot()

        if not Config.BOT_TOKEN:
            logger.error("❌ BOT_TOKEN not configured!")
            return

        # Create application
        app = ApplicationBuilder().token(Config.BOT_TOKEN).build()

        # Add command handlers
        app.add_handler(CommandHandler("start", bot.start_command))

        # Protocol creation handlers
        protocol_patterns = [
            "^create_wireguard_pro$", "^create_temp_wireguard$",
            "^create_shadowsocks$", "^create_temp_shadowsocks$",
            "^create_v2ray_ws$", "^create_trojan_ws$"
        ]

        for pattern in protocol_patterns:
            app.add_handler(CallbackQueryHandler(bot.create_protocol_config, pattern=pattern))

        # Payment handlers
        app.add_handler(CallbackQueryHandler(bot.show_pricing, pattern="^show_pricing$"))
        payment_patterns = ["^buy_day$", "^buy_week$", "^buy_month$", "^buy_year$"]
        for pattern in payment_patterns:
            app.add_handler(CallbackQueryHandler(bot.process_payment, pattern=pattern))

        app.add_handler(CallbackQueryHandler(bot.check_payment, pattern="^check_payment_"))
        app.add_handler(CallbackQueryHandler(bot.payment_help, pattern="^payment_help$"))
        app.add_handler(CallbackQueryHandler(bot.how_to_buy_ton, pattern="^how_to_buy_ton$"))

        # Menu handlers
        app.add_handler(CallbackQueryHandler(bot.my_configs, pattern="^my_configs$"))
        app.add_handler(CallbackQueryHandler(bot.user_stats, pattern="^user_stats$"))
        app.add_handler(CallbackQueryHandler(bot.server_info, pattern="^server_info$"))
        app.add_handler(CallbackQueryHandler(bot.help_menu, pattern="^help_menu$"))
        app.add_handler(CallbackQueryHandler(bot.referral_program, pattern="^referral_program$"))

        # Navigation handlers
        app.add_handler(CallbackQueryHandler(bot.back_to_menu, pattern="^back_to_menu$"))

        # Error handler
        async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
            """Handle errors gracefully"""
            logger.error(f"Exception while handling update: {context.error}")

            if isinstance(update, Update) and update.callback_query:
                try:
                    await update.callback_query.answer("❌ Произошла ошибка. Попробуйте позже.")
                except:
                    pass

        app.add_error_handler(error_handler)

        # Initialize and run
        async def post_init(application):
            try:
                await bot.initialize()

                # Set bot commands
                commands = [
                    BotCommand("start", "🚀 Запустить SafeZone Hub"),
                    BotCommand("help", "❓ Помощь и FAQ"),
                    BotCommand("status", "📊 Статус подписки"),
                    BotCommand("configs", "📋 Мои конфигурации")
                ]
                await application.bot.set_my_commands(commands)

                # Set bot description
                await application.bot.set_my_description(
                    "🛡 SafeZone Hub - Продвинутый VPN с обходом DPI\n\n"
                    "🔒 Протоколы: WireGuard, ShadowSocks, V2Ray, Trojan\n"
                    "🏦 Банковские порты для максимального обхода\n"
                    "💰 Оплата через TON Blockchain"
                )

                logger.info("🎯 Bot configured successfully")

            except Exception as e:
                logger.error(f"Post-init error: {e}")

        app.post_init = post_init

        # Enhanced startup logging
        print("\n" + "=" * 50)
        print("🛡  SAFEZONEHUB VPN BOT")
        print("=" * 50)
        print(f"🌐 Domain: {Config.PRIMARY_DOMAIN}")
        print(f"💰 TON Wallet: {Config.TON_WALLET_ADDRESS}")
        print(f"🏦 Banking Ports: {list(Config.BANKING_PORTS.keys())}")
        print(f"📊 Servers: {len(Config.SERVERS)}")

        for server in Config.SERVERS:
            print(f"   🌍 {server.name} ({server.location})")

        print("=" * 50)
        print("🚀 Starting bot...")
        print("=" * 50 + "\n")

        logger.info("✅ SafeZone Hub VPN Bot started successfully!")

        # Run with polling
        app.run_polling(
            drop_pending_updates=True,
            allowed_updates=["message", "callback_query"]
        )

    except KeyboardInterrupt:
        print("\n🛑 Bot stopped by user")
        logger.info("🛑 Bot stopped by user")
    except Exception as e:
        print(f"\n💥 Critical error: {e}")
        logger.error(f"💥 Critical error: {e}")
        raise
    finally:
        print("🔄 Cleaning up...")
        logger.info("🔄 Bot shutdown completed")


if __name__ == '__main__':
    main()
