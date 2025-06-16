#!/usr/bin/env python3


import os
from dotenv import load_dotenv

load_dotenv('/opt/vpnbot/.env')
import json
import base64
import secrets
import logging
import asyncio
import subprocess
import aiosqlite
import aiohttp
import qrcode
import urllib.parse
import tempfile
import socket
import uuid
import time
import hashlib
import ipaddress
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes
)
from collections import deque
import sqlite3

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
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
    banking_ports: List[int] = field(default_factory=lambda: [443])
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
    BOT_TOKEN = os.getenv("VPN_BOT_TOKEN", "")
    assert BOT_TOKEN, "VPN_BOT_TOKEN environment variable is required"

    DB_PATH = os.getenv("VPN_DB_PATH", "/etc/vpnbot/vpnbot.db")
    ADMIN_IDS = [
        int(x.strip()) for x in os.getenv("VPN_ADMIN_IDS", "1981730098").split(",")
    ]

    TON_WALLET_ADDRESS = os.getenv("TON_WALLET_ADDRESS", "")
    TON_API_KEY = os.getenv("TON_API_KEY", "")
    TON_API_URL = os.getenv("TON_API_URL", "https://toncenter.com/api/v2/")

    PRIMARY_DOMAIN = os.getenv("VPN_PRIMARY_DOMAIN", "safezonehub.com")

    WG_BIN = os.getenv("WG_BIN", "/usr/bin/wg")
    WG_INTERFACE = os.getenv("WG_INTERFACE", "wg0")
    WG_SERVER_PRIVATE_KEY_FILE = os.getenv(
        "WG_SERVER_PRIVATE_KEY_FILE", "/etc/wireguard/server.key"
    )
    WG_CONFIG_PATH = os.getenv("WG_CONFIG_PATH", "/etc/wireguard/wg0.conf")

    CERT_PATH = os.getenv("VPN_CERT_PATH", "/etc/ssl/certs/safezonehub.crt")
    CERT_KEY_PATH = os.getenv("VPN_CERT_KEY_PATH", "/etc/ssl/private/safezonehub.key")

    # ⇣ 100 "легитимных" сервис-портов — DPI пропускает, клиенты видят как привычный трафик
    BANKING_PORTS: dict[int, str] = {
        110: "POP3",             111:  "RPCBind",          113:  "IDENT",         119:  "NNTP",
        123: "NTP",              135:  "MS-RPC",           137:  "NetBIOS-NS",    138:  "NetBIOS-DGM",
        139: "NetBIOS-SSN",      143:  "IMAP",             161:  "SNMP",          162:  "SNMP-Trap",
        179: "BGP",              194:  "IRC",              389:  "LDAP",          443:  "HTTPS",
        465: "SMTPS",            512:  "REXEC",            513:  "RLOGIN",        514:  "SYSLOG/RSH",
        515: "LPR",              520:  "RIP",              521:  "RIPng",         522:  "ULP",
        587: "SMTP-SUBM",        593:  "RPC/HTTP",         636:  "LDAPS",         873:  "RSYNC",
        902: "VMware-Auth",      989:  "FTPS-DATA",        990:  "FTPS-CTRL",     993:  "IMAPS",
        995: "POP3S",           1194:  "OpenVPN",         1433:  "MS-SQL",       1521:  "Oracle-DB",
       1723: "PPTP",            1812:  "RADIUS-Auth",     1813:  "RADIUS-Acct",  2049:  "NFS",
       2083: "cPanel-SSL",      2087:  "WHM-SSL",         2096:  "Webmail-SSL",  2222:  "DirectAdmin",
       2375: "Docker-Plain",    2376:  "Docker-TLS",      2483:  "Oracle-Net",   2484:  "Oracle-Net-SSL",
       3128: "HTTP-Proxy",      3306:  "MySQL",           3389:  "RDP",          3478:  "STUN",
       3690: "Subversion",      4000:  "Generic",         4190:  "Sieve",        4333:  "MySQL-Alt",
       4500: "IPsec-NAT-T",     4567:  "MariaDB-Galera",  5000:  "UPnP/Synology",
       5060: "SIP",             5061:  "SIP-TLS",         5222:  "XMPP-Client",  5223:  "XMPP-SSL",
       5228: "Google-FCM",      5269:  "XMPP-Server",     5432:  "PostgreSQL",
       5672: "AMQP/Rabbit",     5900:  "VNC",             5984:  "CouchDB",      6000:  "X11",
       6379: "Redis",           6667:  "IRC-Alt",         6697:  "IRC-TLS",
       7001: "Elasticsearch",   7002:  "Elastic-TLS",     7070:  "WebSocket/RTSP",
       7443: "HTTPS-Alt",       7777:  "Game/Generic",    8000:  "HTTP-Alt",
       8080: "HTTP-Proxy",      8081:  "HTTP-Alt-2",      8088:  "HTTP-Alt-3",
       8090: "HTTP-Alt-4",      8181:  "JBoss/Node",      8200:  "UPnP-Alt",
       8443: "HTTPS-Alt",       8883:  "MQTT-SSL",        8888:  "HTTP-Proxy-Alt",
       9418: "Git",            10000: "Webmin",          11211: "Memcached"
    }

    SS_METHOD = os.getenv("SS_METHOD", "chacha20-ietf-poly1305")
    SS_MANAGER_PORT = int(os.getenv("SS_MANAGER_PORT", "4000"))
    SS_PLUGIN_BIN = os.getenv("SS_PLUGIN_BIN", "/usr/local/bin/v2ray-plugin")
    SS_PLUGIN_OPTS_SERVER = os.getenv(
        "SS_PLUGIN_OPTS_SERVER",
        "server;tls;host={domain};path=/v2ray;"
        "cert=/etc/v2ray-cert/fullchain.pem;"
        "key=/etc/v2ray-cert/privkey.pem",
    )

    PRICES = {
        "day": PriceConfig(0.3, 25, 0.30),
        "week": PriceConfig(1.5, 100, 1.20),
        "month": PriceConfig(5.0, 300, 3.50),
        "year": PriceConfig(40.0, 2500, 30.0),
    }

    SERVERS = [
        ServerConfig(
            id="de1",
            name="🇩🇪 Frankfurt Banking",
            ip=os.getenv("VPN_SERVER_IP", "45.77.65.249"),
            domain=os.getenv("VPN_SERVER_DOMAIN", "de.safezonehub.com"),
            location="Frankfurt, Germany",
            banking_ports=list(BANKING_PORTS.keys()),
        )
    ]

    FREE_DAILY_MINUTES = int(os.getenv("VPN_FREE_DAILY_MINUTES", "30"))
    TEMP_CONFIG_LIFETIME = int(os.getenv("VPN_TEMP_CONFIG_LIFETIME", "30"))


    @classmethod
    def validate_environment(cls):
        """Validate environment and required files"""
        # Check WireGuard binary
        if not os.path.exists(cls.WG_BIN):
            raise RuntimeError(f"WireGuard binary not found at {cls.WG_BIN}")

        # Check WireGuard server key
        if not os.path.exists(cls.WG_SERVER_PRIVATE_KEY_FILE):
            raise RuntimeError(f"WireGuard server key not found at {cls.WG_SERVER_PRIVATE_KEY_FILE}")

        # Check WireGuard config directory
        wg_config_dir = os.path.dirname(cls.WG_CONFIG_PATH)
        if not os.path.exists(wg_config_dir):
            raise RuntimeError(f"WireGuard config directory not found at {wg_config_dir}")

        # Check SSL certificates
        if not os.path.exists(cls.CERT_PATH):
            raise RuntimeError(f"SSL certificate not found at {cls.CERT_PATH}")
        if not os.path.exists(cls.CERT_KEY_PATH):
            raise RuntimeError(f"SSL key not found at {cls.CERT_KEY_PATH}")

        # Check database directory
        db_dir = os.path.dirname(cls.DB_PATH)
        if not os.path.exists(db_dir):
            raise RuntimeError(f"Database directory not found at {db_dir}")

        # Set secure permissions for database
        if os.path.exists(cls.DB_PATH):
            os.chmod(cls.DB_PATH, 0o600)


# Database Manager
class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._pool = None
        self._pool_lock = asyncio.Lock()

    async def get_connection(self):
        """Get a connection from the pool or create a new one"""
        if self._pool is None:
            async with self._pool_lock:
                if self._pool is None:
                    self._pool = await aiosqlite.connect(self.db_path)
                    # Enable foreign keys
                    await self._pool.execute("PRAGMA foreign_keys = ON")
                    # Enable JSON support
                    await self._pool.execute("PRAGMA json = ON")
        return self._pool

    async def close(self):
        """Close the database connection"""
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def init_database(self) -> None:
        """
        Создаёт (или мигрирует) схему БД.
        Таблицы: users • payments • servers • configs • port_holds • ip_holds
        Любая новая колонка добавляется «на лету», поэтому данные не теряются.
        """
        try:
            db = await self.get_connection()

            # ---------- USERS ----------
            await db.execute("""
                             CREATE TABLE IF NOT EXISTS users
                             (
                                 user_id
                                 INTEGER
                                 PRIMARY
                                 KEY,
                                 username
                                 TEXT,
                                 first_name
                                 TEXT,
                                 last_name
                                 TEXT,
                                 language_code
                                 TEXT,
                                 created_at
                                 TIMESTAMP
                                 DEFAULT
                                 CURRENT_TIMESTAMP,
                                 last_activity
                                 TIMESTAMP
                                 DEFAULT
                                 CURRENT_TIMESTAMP,
                                 daily_usage_minutes
                                 INTEGER
                                 DEFAULT
                                 0,
                                 last_usage_reset
                                 TIMESTAMP
                                 DEFAULT
                                 CURRENT_TIMESTAMP,
                                 status
                                 TEXT
                                 DEFAULT
                                 'free',
                                 subscription_type
                                 TEXT,
                                 subscription_expires
                                 TIMESTAMP,
                                 referral_code
                                 TEXT
                                 UNIQUE,
                                 referred_by
                                 INTEGER,
                                 FOREIGN
                                 KEY
                             (
                                 referred_by
                             ) REFERENCES users
                             (
                                 user_id
                             )
                                 )
                             """)

            # миграция users
            await self._ensure_columns(
                db, "users",
                language_code="TEXT",
                subscription_type="TEXT",
                subscription_expires="TIMESTAMP"
            )

            # ---------- PAYMENTS ----------
            await db.execute("""
                             CREATE TABLE IF NOT EXISTS payments
                             (
                                 id
                                 INTEGER
                                 PRIMARY
                                 KEY
                                 AUTOINCREMENT,
                                 payment_id
                                 TEXT
                                 UNIQUE,
                                 user_id
                                 INTEGER
                                 NOT
                                 NULL,
                                 amount
                                 REAL
                                 NOT
                                 NULL,
                                 currency
                                 TEXT
                                 NOT
                                 NULL,
                                 subscription_type
                                 TEXT
                                 NOT
                                 NULL,
                                 status
                                 TEXT
                                 DEFAULT
                                 'pending',
                                 comment
                                 TEXT,
                                 created_at
                                 TIMESTAMP
                                 DEFAULT
                                 CURRENT_TIMESTAMP,
                                 completed_at
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

            # миграция payments
            await self._ensure_columns(
                db, "payments",
                payment_id="TEXT UNIQUE"
            )

            await db.execute("""
                             CREATE INDEX IF NOT EXISTS idx_payments_status
                                 ON payments(status)
                             """)

            # ---------- SERVERS ----------
            await db.execute("""
                             CREATE TABLE IF NOT EXISTS servers
                             (
                                 id
                                 TEXT
                                 PRIMARY
                                 KEY,
                                 name
                                 TEXT,
                                 ip
                                 TEXT,
                                 domain
                                 TEXT,
                                 location
                                 TEXT,
                                 banking_ports
                                 TEXT,
                                 max_users
                                 INTEGER
                                 DEFAULT
                                 1000,
                                 is_active
                                 BOOLEAN
                                 DEFAULT
                                 1
                             )
                             """)

            # апсерт серверов из конфигурации
            for s in Config.SERVERS:
                await db.execute("""
                                 INSERT INTO servers (id, name, ip, domain, location,
                                                      banking_ports, max_users, is_active)
                                 VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO
                                 UPDATE SET
                                     name = excluded.name,
                                     ip = excluded.ip,
                                     domain = excluded.domain,
                                     location = excluded.location,
                                     banking_ports = excluded.banking_ports,
                                     max_users = excluded.max_users,
                                     is_active = excluded.is_active
                                 """, (
                                     s.id, s.name, s.ip, s.domain, s.location,
                                     json.dumps(s.banking_ports), s.max_users, int(s.is_active)
                                 ))

            # ---------- CONFIGS ----------
            await db.execute("""
                             CREATE TABLE IF NOT EXISTS configs
                             (
                                 id
                                 INTEGER
                                 PRIMARY
                                 KEY
                                 AUTOINCREMENT,
                                 user_id
                                 INTEGER,
                                 protocol
                                 TEXT,
                                 server_id
                                 TEXT,
                                 config_name
                                 TEXT,
                                 port
                                 INTEGER,
                                 client_ip
                                 TEXT,
                                 config_data
                                 TEXT,
                                 created_at
                                 TIMESTAMP
                                 DEFAULT
                                 CURRENT_TIMESTAMP,
                                 expires_at
                                 TIMESTAMP,
                                 is_active
                                 BOOLEAN
                                 DEFAULT
                                 1,
                                 FOREIGN
                                 KEY
                             (
                                 user_id
                             ) REFERENCES users
                             (
                                 user_id
                             ),
                                 FOREIGN KEY
                             (
                                 server_id
                             ) REFERENCES servers
                             (
                                 id
                             )
                                 )
                             """)

            await self._ensure_columns(db, "configs", config_name="TEXT")

            # ---------- PORT HOLDS ----------
            await db.execute("""
                             CREATE TABLE IF NOT EXISTS port_holds
                             (
                                 id
                                 INTEGER
                                 PRIMARY
                                 KEY
                                 AUTOINCREMENT,
                                 server_id
                                 TEXT,
                                 port
                                 INTEGER,
                                 protocol
                                 TEXT,
                                 created_at
                                 TIMESTAMP
                                 DEFAULT
                                 CURRENT_TIMESTAMP,
                                 expires_at
                                 TIMESTAMP
                                 DEFAULT (
                                 datetime
                             (
                                 'now',
                                 '+5 minutes'
                             )),
                                 FOREIGN KEY
                             (
                                 server_id
                             ) REFERENCES servers
                             (
                                 id
                             ),
                                 UNIQUE
                             (
                                 server_id,
                                 port
                             )
                                 )
                             """)

            # ---------- IP HOLDS ----------
            await db.execute("""
                             CREATE TABLE IF NOT EXISTS ip_holds
                             (
                                 id
                                 INTEGER
                                 PRIMARY
                                 KEY
                                 AUTOINCREMENT,
                                 server_id
                                 TEXT,
                                 client_ip
                                 TEXT,
                                 protocol
                                 TEXT,
                                 created_at
                                 TIMESTAMP
                                 DEFAULT
                                 CURRENT_TIMESTAMP,
                                 expires_at
                                 TIMESTAMP
                                 DEFAULT (
                                 datetime
                             (
                                 'now',
                                 '+5 minutes'
                             )),
                                 FOREIGN KEY
                             (
                                 server_id
                             ) REFERENCES servers
                             (
                                 id
                             ),
                                 UNIQUE
                             (
                                 server_id,
                                 client_ip
                             )
                                 )
                             """)

            # индексы для auto-cleanup
            await db.execute("""
                             CREATE INDEX IF NOT EXISTS idx_configs_expire
                                 ON configs(expires_at, is_active)
                             """)
            await db.execute("""
                             CREATE INDEX IF NOT EXISTS idx_port_holds_expire
                                 ON port_holds(expires_at)
                             """)
            await db.execute("""
                             CREATE INDEX IF NOT EXISTS idx_ip_holds_expire
                                 ON ip_holds(expires_at)
                             """)

            await db.commit()
            logger.info("✅ Database schema ready")

        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            raise

    async def _ensure_columns(self, db, table: str, **cols) -> None:
        """
        Добавляет недостающие колонки в существующую таблицу.
        cols = {"column_name": "SQL_TYPE", ...}
        """
        cursor = await db.execute(f"PRAGMA table_info({table})")
        present = {row[1] for row in await cursor.fetchall()}

        for name, sql_type in cols.items():
            if name not in present:
                await db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}")

    async def cleanup_expired_holds(self):
        """Clean up expired port and IP holds"""
        db = await self.get_connection()
        await db.execute("DELETE FROM port_holds WHERE expires_at < datetime('now')")
        await db.execute("DELETE FROM ip_holds WHERE expires_at < datetime('now')")
        await db.commit()

    async def reserve_port(self, server_id: str, port: int, protocol: str) -> bool:
        """Reserve a port for a specific protocol"""
        db = await self.get_connection()
        try:
            await db.execute(
                "INSERT INTO port_holds (server_id, port, protocol) VALUES (?, ?, ?)",
                (server_id, port, protocol)
            )
            await db.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    async def reserve_ip(self, server_id: str, ip: str, protocol: str) -> bool:
        """Reserve an IP address for a specific protocol"""
        db = await self.get_connection()
        try:
            await db.execute(
                "INSERT INTO ip_holds (server_id, client_ip, protocol) VALUES (?, ?, ?)",
                (server_id, ip, protocol)
            )
            await db.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    async def release_port(self, server_id: str, port: int):
        """Release a reserved port"""
        db = await self.get_connection()
        await db.execute(
            "DELETE FROM port_holds WHERE server_id = ? AND port = ?",
            (server_id, port)
        )
        await db.commit()

    async def release_ip(self, server_id: str, ip: str):
        """Release a reserved IP address"""
        db = await self.get_connection()
        await db.execute(
            "DELETE FROM ip_holds WHERE server_id = ? AND client_ip = ?",
            (server_id, ip)
        )
        await db.commit()


# TON Payment Manager
class TONPaymentManager:
    def __init__(self, api_key: str, wallet_address: str):
        self.api_key = api_key
        self.wallet_address = wallet_address
        self.session = None
        self._pending_payments_cleanup_job = None
        self.db = None  # Will be set during initialization

    async def initialize(self):
        """Initialize payment manager"""
        self.session = aiohttp.ClientSession()
        self.db = DatabaseManager(Config.DB_PATH)  # Create database manager
        await self.db.init_database()  # Initialize database
        self._pending_payments_cleanup_job = asyncio.create_task(self._cleanup_pending_payments())

    async def _cleanup_pending_payments(self):
        """Periodically check and cleanup pending payments"""
        while True:
            try:
                db = await self.db.get_connection()
                # Check if payment_id column exists
                cursor = await db.execute("PRAGMA table_info(payments)")
                columns = {row[1] for row in await cursor.fetchall()}

                if 'payment_id' not in columns:
                    logger.info("payment_id column not found in payments table, skipping cleanup")
                    await asyncio.sleep(300)  # Check every 5 minutes
                    continue

                # Get pending payments older than 1 hour
                cursor = await db.execute("""
                                          SELECT id, payment_id, user_id, amount, currency, subscription_type
                                          FROM payments
                                          WHERE status = 'pending'
                                            AND created_at < datetime('now', '-1 hour')
                                          """)
                pending_payments = await cursor.fetchall()

                for payment in pending_payments:
                    payment_id = payment[1]
                    # Check payment status
                    if await self.check_payment_status(payment_id):
                        # Process successful payment
                        await self.process_successful_payment(payment_id)
                    else:
                        # Mark as failed if payment is too old
                        await db.execute("""
                                         UPDATE payments
                                         SET status = 'failed'
                                         WHERE payment_id = ?
                                         """, (payment_id,))
                        await db.commit()

            except Exception as e:
                logger.error(f"Error in pending payments cleanup: {e}")

            await asyncio.sleep(300)  # Check every 5 minutes

    async def check_payment_status(self, payment_id: str) -> bool:
        """Check payment status with increased transaction limit"""
        try:
            async with self.session.get(
                    f"{Config.TON_API_URL}getTransactions",
                    params={
                        "address": self.wallet_address,
                        "limit": 200,  # Increased limit
                        "api_key": self.api_key
                    }
            ) as response:
                if response.status != 200:
                    logger.error(f"TON API error: {response.status}")
                    return False

                data = await response.json()
                if not data.get("ok"):
                    logger.error(f"TON API error: {data.get('error')}")
                    return False

                transactions = data.get("result", [])
                for tx in transactions:
                    if await self._verify_transaction(tx, payment_id):
                        return True

                return False

        except Exception as e:
            logger.error(f"Error checking payment status: {e}")
            return False

    async def process_successful_payment(self, payment_id: str) -> bool:
        """Process successful payment with retry logic"""
        try:
            db = await self.db.get_connection()
            # Get payment details
            cursor = await db.execute("""
                                      SELECT user_id, subscription_type
                                      FROM payments
                                      WHERE payment_id = ?
                                        AND status = 'pending'
                                      """, (payment_id,))
            payment = await cursor.fetchone()

            if not payment:
                logger.warning(f"Payment {payment_id} not found or already processed")
                return False

            user_id, subscription_type = payment

            # Update payment status
            await db.execute("""
                             UPDATE payments
                             SET status       = 'completed',
                                 completed_at = CURRENT_TIMESTAMP
                             WHERE payment_id = ?
                             """, (payment_id,))

            # Update user subscription
            subscription_end = None
            if subscription_type == "day":
                subscription_end = datetime.now() + timedelta(days=1)
            elif subscription_type == "week":
                subscription_end = datetime.now() + timedelta(weeks=1)
            elif subscription_type == "month":
                subscription_end = datetime.now() + timedelta(days=30)
            elif subscription_type == "year":
                subscription_end = datetime.now() + timedelta(days=365)

            if subscription_end:
                await db.execute("""
                                 UPDATE users
                                 SET status           = 'premium',
                                     subscription_end = ?
                                 WHERE user_id = ?
                                 """, (subscription_end, user_id))

            await db.commit()
            return True

        except Exception as e:
            logger.error(f"Error processing payment {payment_id}: {e}")
            return False

    async def close(self):
        """Cleanup resources"""
        if self._pending_payments_cleanup_job:
            self._pending_payments_cleanup_job.cancel()
            try:
                await self._pending_payments_cleanup_job
            except asyncio.CancelledError:
                pass

        if self.session:
            await self.session.close()

        if self.db:
            await self.db.close()


# Protocol Configuration Generator
class ProtocolGenerator:
    def __init__(self):
        self._server_private_key = None
        self._server_private_key_lock = asyncio.Lock()

    async def _get_server_private_key(self) -> str:
        """Get cached server private key with proper locking"""
        if self._server_private_key is None:
            async with self._server_private_key_lock:
                if self._server_private_key is None:
                    try:
                        self._server_private_key = Path(Config.WG_SERVER_PRIVATE_KEY_FILE).read_text().strip()
                    except Exception as e:
                        logger.error(f"Error reading WireGuard server key: {e}")
                        raise
        return self._server_private_key

    async def _get_available_port(self, server: ServerConfig, protocol: ProtocolType) -> int:
        """Get available port for protocol with proper locking"""
        # если у сервера нет своего списка – берём общий
        available_ports = server.banking_ports.copy() or list(Config.BANKING_PORTS.keys())

        # Get used ports from database
        db = await self.db.get_connection()
        cursor = await db.execute("""
            SELECT port FROM configs
            WHERE server_id = ? AND is_active = TRUE
            UNION ALL
            SELECT port FROM port_holds
            WHERE server_id = ?
        """, (server.id, server.id))
        used_ports = {row[0] for row in await cursor.fetchall()}

        # If no banking ports, use protocol-specific fallback range
        if not available_ports:
            logger.warning(
                f"No banking ports configured for server {server.id}, using fallback range"
            )
            fallback_ranges = {
                ProtocolType.WIREGUARD: range(8443, 8500),
                ProtocolType.SHADOWSOCKS: range(8500, 8600),
                ProtocolType.V2RAY: range(8600, 8700),
                ProtocolType.TROJAN: range(8700, 8800),
            }

            # Try to find available port in fallback range
            for port in fallback_ranges.get(protocol, range(8443, 9000)):
                if port not in used_ports:
                    # Try to reserve the port
                    if await self.db.reserve_port(server.id, port, protocol.value):
                        return port
            raise Exception("No available ports found")

        # Filter out used ports
        available_ports = [p for p in available_ports if p not in used_ports]

        if not available_ports:
            raise Exception("No available ports found")

        # Try to reserve a random port
        while available_ports:
            port = secrets.choice(available_ports)
            if await self.db.reserve_port(server.id, port, protocol.value):
                return port
            available_ports.remove(port)

        raise Exception("No available ports found")

    async def generate_wireguard_config(self, user_id: str, server: ServerConfig, config_name: str = None) -> dict:
        """Generate WireGuard configuration"""
        try:
            # Generate keys
            private_key = subprocess.check_output([Config.WG_BIN, "genkey"]).decode().strip()
            public_key = subprocess.check_output([Config.WG_BIN, "pubkey"], input=private_key.encode()).decode().strip()

            # Get server's public key
            server_private_key = await self._get_server_private_key()
            server_public_key = subprocess.check_output([Config.WG_BIN, "pubkey"],
                                                        input=server_private_key.encode()).decode().strip()

            # Get next available IP
            client_ip = await self._get_next_ip(server.id, ProtocolType.WIREGUARD)

            # Get available port
            server_port = await self._get_available_port(server, ProtocolType.WIREGUARD)

            # Create configuration
            config_str = f"""[Interface]
PrivateKey = {private_key}
Address = {client_ip}/32
DNS = 1.1.1.1

[Peer]
PublicKey = {server_public_key}
AllowedIPs = 0.0.0.0/0
Endpoint = {server.domain}:{server_port}
PersistentKeepalive = 25"""

            # Add client to server
            await self._add_wg_client_on_server(server, public_key, client_ip)

            return {
                'client_config': config_str,
                'port': server_port,
                'client_ip': client_ip,
                'public_key': public_key,
                'server_public_key': server_public_key
            }
        except Exception as e:
            logger.error(f"Error generating WireGuard config: {e}")
            return None

    # ----------------------------------------------------------------------
    async def generate_shadowsocks_config(
            self,
            user_id: str,
            server: ServerConfig,
            config_name: str | None = None,
    ) -> dict | None:
        """
        Создаёт TLS-конфиг Shadowsocks (v2ray-plugin WebSocket).

        Возвращает dict, который потом кладётся в БД и передаётся в _send().
        """
        try:
            # 1) пароль
            password = secrets.token_hex(16)

            # 2) свободный банковский / fallback-порт
            server_port = await self._get_available_port(
                server, ProtocolType.SHADOWSOCKS
            )

            # 3) регистрируем в ss-manager (mode=tcp_and_udp + TLS-плагин)
            await self._add_ss_password_on_server(
                server, server_port, password
            )

            # 4) клиентские plugin-opts (на клиенте сертификат не нужен)
            plugin_opts_cli = f"tls;host={server.domain};path=/v2ray"

            # 5) ss:// URI по SIP002  --------------------------------------
            userinfo = f"{Config.SS_METHOD}:{password}"
            hostport = f"{server.domain}:{server_port}"
            base64_id = base64.urlsafe_b64encode(
                f"{userinfo}@{hostport}".encode()
            ).decode().rstrip("=")  # spec: без «=»

            plugin_param = urllib.parse.quote_plus(
                f"v2ray-plugin;{plugin_opts_cli}"
            )

            ss_uri = f"ss://{base64_id}?plugin={plugin_param}"

            # 6) результат
            return {
                "client_config": ss_uri,
                "port": server_port,  # для БД
                "server_port": server_port,  # для отправки в UI
                "password": password,
                "server_domain": server.domain,
                "method": Config.SS_METHOD,
                "plugin": "v2ray-plugin",
                "plugin_opts": plugin_opts_cli,
                "config_name": config_name or f"ss-{server.id}-{user_id}",
            }

        except Exception as e:
            logger.error(f"Error generating Shadowsocks config: {e}")
            return None

    async def _add_wg_client_on_server(self, server: ServerConfig, public_key: str, client_ip: str):
        """Add WireGuard client to server"""
        try:
            # Add peer to server configuration
            cmd = f"{Config.WG_BIN} set {Config.WG_INTERFACE} peer {public_key} allowed-ips {client_ip}/32"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                raise Exception(f"Failed to add WG client: {stderr.decode()}")

            # Add peer to config file
            peer_config = f"\n[Peer]\nPublicKey = {public_key}\nAllowedIPs = {client_ip}/32\n"

            try:
                with open(Config.WG_CONFIG_PATH, 'a') as f:
                    f.write(peer_config)
            except Exception as e:
                logger.error(f"Failed to write to WG config file: {e}")
                # Continue even if file write fails - the peer is already added via wg command

        except Exception as e:
            logger.error(f"Error adding WG client: {e}")
            raise

    async def _add_ss_password_on_server(self, server: ServerConfig, server_port: int, password: str):
        """Add ShadowSocks password to server"""
        try:
            payload = {
                "server_port": server_port,
                "password":     password,
                "method":       Config.SS_METHOD,
                "mode":         "tcp_and_udp",
                "plugin":       Config.SS_PLUGIN_BIN,
                "plugin_opts":  Config.SS_PLUGIN_OPTS_SERVER.format(domain=server.domain),
            }
            # ss-manager требует префикс «add: »
            data = f"add:{json.dumps(payload)}".encode()

            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self._send_ss_command, data)
        except Exception as e:
            logger.error(f"Error adding SS password: {e}")
            raise

    def _send_ss_command(self, data: bytes):
        """Send command to ShadowSocks manager"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(data, ("127.0.0.1", Config.SS_MANAGER_PORT))
        except Exception as e:
            logger.error(f"Error sending SS command: {e}")
            raise

    async def _get_next_ip(self, server_id: str, protocol: ProtocolType) -> str:
        """
        Allocate the next free /32 address from 10.66.66.0/24 for a given server.

        1. Собираем все занятые IP (активные + временные брони).
        2. Проходим по пулу 10.66.66.10-253, ищем первый свободный.
        3. Пытаемся «забронировать» его через reserve_ip().
           Если бронь прошла успешно — возвращаем адрес.
        4. Если пул закончился — бросаем Exception.
        """
        # Шаг 1: получаем занятые IP-адреса одним запросом
        db = await self.db.get_connection()
        cursor = await db.execute("""
                                  SELECT client_ip
                                  FROM configs
                                  WHERE server_id = ?
                                    AND is_active = TRUE

                                  UNION

                                  SELECT client_ip
                                  FROM ip_holds
                                  WHERE server_id = ?
                                  """, (server_id, server_id))
        busy_ips = {row[0] for row in await cursor.fetchall() if row[0]}

        # Шаг 2: перебираем пул адресов
        network = ipaddress.ip_network("10.66.66.0/24")
        for host in range(10, 254):  # 10.66.66.10-253
            candidate_ip = str(network.network_address + host)

            if candidate_ip in busy_ips:
                continue

            # Шаг 3: пытаемся зарезервировать IP в ip_holds
            try:
                if await self.db.reserve_ip(server_id, candidate_ip, protocol.value):
                    return candidate_ip
            except Exception as e:
                # Если бронь не удалась — логируем и ищем дальше
                logger.error(f"Reserve IP failed for {candidate_ip}: {e}")

        # Шаг 4: свободных адресов не осталось
        raise Exception("No available IP addresses in 10.66.66.0/24")

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


# Main VPN Bot Class
class SafeZoneBot:
    def __init__(self):
        self.bot = None
        self.db = None
        self.payment_manager = None
        self.protocol_generator = None
        self.rate_limiter = {}  # user_id -> deque of timestamps
        self.rate_limit_window = 60  # seconds
        self.rate_limit_max_requests = 5  # requests per window

    def _check_rate_limit(self, user_id: str) -> bool:
        """Check if user has exceeded rate limit using deque"""
        now = datetime.now()

        # Initialize deque for new users
        if user_id not in self.rate_limiter:
            self.rate_limiter[user_id] = deque(maxlen=self.rate_limit_max_requests)

        # Remove old timestamps
        while self.rate_limiter[user_id] and (now - self.rate_limiter[user_id][0]) > timedelta(
                seconds=self.rate_limit_window):
            self.rate_limiter[user_id].popleft()

        # Check if limit exceeded
        if len(self.rate_limiter[user_id]) >= self.rate_limit_max_requests:
            return False

        # Add current timestamp
        self.rate_limiter[user_id].append(now)
        return True

    async def initialize(self, app: Application):
        try:
            self.db = DatabaseManager(Config.DB_PATH)
            self.payment_manager = TONPaymentManager(
                Config.TON_API_KEY, Config.TON_WALLET_ADDRESS
            )
            self.protocol_generator = ProtocolGenerator()
            self.protocol_generator.db = self.db

            await self.db.init_database()
            await self.payment_manager.initialize()

            logger.info("SafeZone Bot initialized successfully")
        except Exception as e:
            logger.error(f"Bot initialization failed: {e}")
            raise

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

        welcome_text = f"""
🛡 **SafeZone Hub - Продвинутый VPN**

Добро пожаловать, {getattr(user, 'first_name', 'Пользователь')}! 

📊 **Статус:** {status_text}

🔒 **Доступные протоколы:**
• 🔑 **WireGuard** - быстрый и надёжный
• 🥷 **ShadowSocks** - обходит блокировки DPI
• 🚀 **V2Ray** - HTTPS маскировка
• 🛡 **Trojan** - максимальная скрытность

🏦 **Банковские порты:** 443, 465, 993, 8443
🔐 **Домен:** {Config.PRIMARY_DOMAIN}

Выберите действие:
"""

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
                 InlineKeyboardButton("🥷 Shadowsocks TLS", callback_data="create_shadowsocks_tls")],
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

    async def _create_or_update_user(self, user):
        """Create or update user in database with safe column handling"""
        user_id = str(user.id)
        username = user.username or ""
        first_name = getattr(user, 'first_name', '') or ""
        last_name = getattr(user, 'last_name', '') or ""
        language_code = getattr(user, 'language_code', 'ru') or "ru"

        # Generate referral code
        ref_code = f"REF{secrets.token_hex(4).upper()}"

        async with aiosqlite.connect(Config.DB_PATH) as conn:
            # Check if user exists
            cursor = await conn.execute("SELECT user_id FROM users WHERE user_id = ?", (user_id,))
            existing = await cursor.fetchone()

            if existing:
                # Update existing user - only update safe columns
                try:
                    await conn.execute("""
                                       UPDATE users
                                       SET username      = ?,
                                           last_activity = ?
                                       WHERE user_id = ?
                                       """, (username, datetime.now().isoformat(), user_id))

                    # Try to update additional columns if they exist
                    try:
                        await conn.execute("""
                                           UPDATE users
                                           SET first_name    = ?,
                                               last_name     = ?,
                                               language_code = ?
                                           WHERE user_id = ?
                                           """, (first_name, last_name, language_code, user_id))
                    except Exception:
                        # Columns might not exist in old schema
                        pass

                except Exception as e:
                    logger.error(f"Error updating user: {e}")
            else:
                # Create new user
                try:
                    await conn.execute("""
                                       INSERT INTO users
                                       (user_id, username, first_name, last_name, language_code, referral_code,
                                        last_activity)
                                       VALUES (?, ?, ?, ?, ?, ?, ?)
                                       """, (user_id, username, first_name, last_name, language_code, ref_code,
                                             datetime.now().isoformat()))
                except Exception as e:
                    # Fallback to minimal user creation if columns don't exist
                    logger.warning(f"Failed to create user with full schema: {e}")
                    try:
                        await conn.execute("""
                                           INSERT INTO users (user_id, username, referral_code)
                                           VALUES (?, ?, ?)
                                           """, (user_id, username, ref_code))
                    except Exception as e2:
                        logger.error(f"Failed to create user with minimal schema: {e2}")
                        return

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

        # Parse protocol
        protocol_map = {
            "create_wireguard_pro": (ProtocolType.WIREGUARD, False),
            "create_temp_wireguard": (ProtocolType.WIREGUARD, True),
            "create_shadowsocks_tls": (ProtocolType.SHADOWSOCKS, False),
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
            last_usage_date = datetime.fromisoformat(result[1]).date() if result[1] else None
            daily_usage = result[0] if last_usage_date == today else 0

            if daily_usage >= Config.FREE_DAILY_MINUTES:
                return False, f"🕐 Дневной лимит исчерпан ({Config.FREE_DAILY_MINUTES} мин)."

        return True, None

    async def _create_and_deploy_config(self, query, protocol: ProtocolType,
                                        is_temporary: bool, context: ContextTypes.DEFAULT_TYPE):
        user_id = str(query.from_user.id)
        server = Config.SERVERS[0]  # Using first server for now

        try:
            # Generate configuration based on protocol
            if protocol == ProtocolType.WIREGUARD:
                config_data = await self.protocol_generator.generate_wireguard_config(user_id, server)
            elif protocol == ProtocolType.SHADOWSOCKS:
                config_data = await self.protocol_generator.generate_shadowsocks_config(user_id, server)
            elif protocol == ProtocolType.V2RAY:
                config_data = await self.protocol_generator.generate_v2ray_config(server, user_id)
            elif protocol == ProtocolType.TROJAN:
                config_data = await self.protocol_generator.generate_trojan_config(server, user_id)
            else:
                await query.edit_message_text("❌ Неподдерживаемый протокол")
                return

            if not config_data:
                await query.edit_message_text("❌ Ошибка генерации конфигурации")
                return

            # Calculate expiration
            expires_at = None
            if is_temporary:
                expires_at = datetime.now() + timedelta(minutes=Config.TEMP_CONFIG_LIFETIME)

            # Save configuration
            config_id = await self._save_config_to_db(
                user_id=user_id,
                protocol=protocol,
                server_id=server.id,
                config_data=config_data,
                expires_at=expires_at
            )

            # Send configuration to user
            lifetime_text = "Временная" if is_temporary else "Постоянная"
            await self._send_config_to_user(
                query.message.chat_id,
                protocol,
                config_data,
                server,
                expires_at,
                lifetime_text,
                context
            )

            if is_temporary:
                await self._update_user_usage(user_id, Config.TEMP_CONFIG_LIFETIME)

        except Exception as e:
            logger.error(f"Error creating config: {e}")
            await query.edit_message_text(f"❌ Ошибка: {str(e)}")

    async def _save_config_to_db(self, user_id: str, protocol: ProtocolType, server_id: str, config_data: dict,
                                 config_name: str = None, port: int = None, expires_at: datetime = None) -> int:
        """Save configuration to database"""
        try:
            async with aiosqlite.connect(Config.DB_PATH) as db:
                cursor = await db.execute("""
                                          INSERT INTO configs (user_id, protocol, server_id, config_data, config_name,
                                                               port, expires_at, created_at)
                                          VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
                                          """, (
                                              user_id,
                                              protocol.value,
                                              server_id,
                                              json.dumps(config_data),
                                              config_name,
                                              port or config_data.get('port', 443),
                                              expires_at.isoformat() if expires_at else None
                                          ))
                await db.commit()
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Error saving config to database: {e}")
            raise

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
        """Send WireGuard configuration with proper file cleanup"""
        try:
            # Create temporary file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as temp_file:
                # Write config
                temp_file.write(f"[Interface]\n")
                temp_file.write(f"PrivateKey = {config_data['client_private_key']}\n")
                temp_file.write(f"Address = {config_data['client_ip']}/32\n")
                temp_file.write(f"DNS = {config_data['dns']}\n")
                temp_file.write(f"MTU = {config_data['mtu']}\n\n")
                temp_file.write(f"[Peer]\n")
                temp_file.write(f"PublicKey = {config_data['server_public_key']}\n")
                temp_file.write(f"Endpoint = {server.domain}:{config_data['server_port']}\n")
                temp_file.write(f"AllowedIPs = 0.0.0.0/0\n")
                temp_file.write(f"PersistentKeepalive = 25\n")
                temp_file.flush()

                # Send file
                try:
                    await context.bot.send_document(
                        chat_id=chat_id,
                        document=open(temp_file.name, 'rb'),
                        filename=f"wg_{server.id}.conf",
                        caption=(
                            f"🔐 *WireGuard конфигурация*\n\n"
                            f"🌐 Сервер: {server.name}\n"
                            f"📡 Порт: {config_data['server_port']}\n"
                            f"🔄 {lifetime_text}\n\n"
                            f"💡 *Как использовать:*\n"
                            f"1. Скачайте файл\n"
                            f"2. Установите WireGuard\n"
                            f"3. Импортируйте конфиг\n"
                            f"4. Подключитесь"
                        ),
                        parse_mode='Markdown'
                    )
                finally:
                    # Ensure file is deleted even if sending fails
                    try:
                        os.unlink(temp_file.name)
                    except Exception as e:
                        logger.error(f"Error deleting temporary file: {e}")

        except Exception as e:
            logger.error(f"Error sending WireGuard config: {e}")
            raise

    # ----------------------------------------------------------------------
    async def _send_shadowsocks_config(
            self,
            chat_id: int,
            config_data: Dict[str, Any],
            server: ServerConfig,
            expires_at: Optional[datetime],
            lifetime_text: str,
            context: ContextTypes.DEFAULT_TYPE,
    ) -> None:
        """Шлёт пользователю JSON-файл + QR-код Shadowsocks-TLS."""
        json_path = qr_path = None  # чтобы existed в finally

        try:
            ss_uri = config_data["client_config"]
            server_port = config_data["server_port"]
            plugin_opts = config_data["plugin_opts"]

            # ---------- JSON для клиентов ----------
            json_path = tempfile.mktemp(suffix=".json")
            with open(json_path, "w", encoding="utf-8") as fp:
                json.dump(
                    {
                        "server": server.domain,
                        "server_port": server_port,
                        "password": config_data["password"],
                        "method": config_data["method"],
                        "mode": "tcp_and_udp",
                        "plugin": "v2ray-plugin",
                        "plugin_opts": plugin_opts,
                        "local_address": "127.0.0.1",
                        "local_port": 1080,
                        "timeout": 300,
                    },
                    fp,
                    indent=2,
                )

            # ---------- QR-код ----------
            qr = qrcode.QRCode(box_size=8, border=2)
            qr.add_data(ss_uri)
            qr.make(fit=True)
            qr_img = qr.make_image(fill_color="black", back_color="white")
            qr_path = tempfile.mktemp(suffix=".png")
            qr_img.save(qr_path)

            # ---------- подпись ----------
            caption = (
                "🔐 *Shadowsocks-TLS*\n\n"
                f"🌐 Сервер: {server.name}\n"
                f"📡 Порт: `{server_port}`\n"
                f"🔑 Пароль: `{config_data['password']}`\n"
                f"⏱️ {lifetime_text}"
            )
            if expires_at:
                caption += f"\n⚠️ Истекает: {expires_at:%Y-%m-%d %H:%M}"

            caption += (
                "\n\n💡 *Инструкция*"
                "\n1. Скачайте JSON или отсканируйте QR"
                "\n2. Импортируйте в v2rayNG / Shadowrocket"
                "\n3. Подключайтесь"
            )

            # ---------- отправляем ----------
            await context.bot.send_document(
                chat_id=chat_id,
                document=open(json_path, "rb"),
                filename=f"ss_{server.id}.json",
                caption=caption,
                parse_mode="Markdown",
            )

            await context.bot.send_photo(
                chat_id=chat_id,
                photo=open(qr_path, "rb"),
                caption="📱 QR-код для быстрого добавления",
            )

        except Exception as e:
            logger.error(f"Error sending Shadowsocks config: {e}")
            raise

        finally:
            # всегда удаляем временные файлы
            for path in (json_path, qr_path):
                if path and os.path.exists(path):
                    try:
                        os.unlink(path)
                    except Exception as e:
                        logger.error(f"Error deleting temp file {path}: {e}")

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
🆔 **UUID:** `{config_data['uuid'][:8]}...`
🔐 **Транспорт:** WebSocket + TLS
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

    async def _remove_wg_client_from_server(self, server: ServerConfig, public_key: str):
        """Remove WireGuard client from server"""
        try:
            # Remove peer from server configuration
            cmd = f"{Config.WG_BIN} set {Config.WG_INTERFACE} peer {public_key} remove"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                raise Exception(f"Failed to remove WG client: {stderr.decode()}")

        except Exception as e:
            logger.error(f"Error removing WG client: {e}")
            raise

    async def _remove_ss_password_from_server(self, server: ServerConfig, port: int):
        """Remove ShadowSocks password from server"""
        try:
            data = json.dumps({
                "server_port": port,
                "remove": True
            }).encode()

            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self.protocol_generator._send_ss_command, data)
        except Exception as e:
            logger.error(f"Error removing SS password: {e}")
            raise

    async def _cleanup_expired_config(self):
        """Clean up expired configurations"""
        db = await self.db.get_connection()
        try:
            # Get expired configs
            cursor = await db.execute("""
                                      SELECT id, protocol, server_id, port, client_ip
                                      FROM configs
                                      WHERE expires_at < datetime('now')
                                        AND is_active = TRUE
                                      """)
            expired_configs = await cursor.fetchall()

            for config in expired_configs:
                config_id, protocol, server_id, port, client_ip = config
                server = next((s for s in Config.SERVERS if s.id == server_id), None)

                if not server:
                    logger.error(f"Server {server_id} not found for config {config_id}")
                    continue

                # Remove configuration based on protocol
                if protocol == ProtocolType.WIREGUARD.value:
                    await self._remove_wg_client_from_server(server, client_ip)
                elif protocol == ProtocolType.SHADOWSOCKS.value:
                    await self._remove_ss_password_from_server(server, port)

                # Mark config as inactive
                await db.execute("""
                                 UPDATE configs
                                 SET is_active = FALSE
                                 WHERE id = ?
                                 """, (config_id,))

            await db.commit()

        except Exception as e:
            logger.error(f"Error cleaning up expired configs: {e}")

    # Payment handlers
    async def show_pricing(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show pricing information"""
        query = update.callback_query
        await query.answer()

        pricing_text = f"""
💎 **SafeZone Hub Premium**

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

🔒 **Оплата через TON Blockchain**
"""

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
                await query.edit_message_text("""
✅ **Платеж получен!**

🎉 **Подписка активирована!**
⭐ Теперь у вас есть доступ ко всем протоколам.

Возвращайтесь в главное меню для создания конфигураций.
""", reply_markup=InlineKeyboardMarkup([
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
        """Show user configurations"""
        query = update.callback_query
        await query.answer()

        user_id = str(query.from_user.id)

        async with aiosqlite.connect(Config.DB_PATH) as conn:
            cursor = await conn.execute("""
                                        SELECT protocol, port, created_at, expires_at, is_active
                                        FROM configs
                                        WHERE user_id = ?
                                        ORDER BY created_at DESC LIMIT 10
                                        """, (user_id,))

            configs = await cursor.fetchall()

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

                config_text += f"• **{protocol.title()}** (порт {port}) - {status}\n"
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
🥷 **Shadowsocks** - обходит DPI
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
🔐 **Обфускация:** TLS, WebSocket для обхода DPI
"""

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
• Заработано: {referral_earnings:.2f} TON
"""
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
• Shadowsocks стабильно обходит блокировки"""

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
`https://t.me/{context.bot.username}?start={referral_code}`

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

    async def error_handler(self, update: object, context: ContextTypes.DEFAULT_TYPE):
        """Handle errors with proper logging"""
        try:
            # Log the error
            logger.error(f"Update {update} caused error {context.error}")

            # Get user info if available
            user_info = ""
            if update and hasattr(update, 'effective_user'):
                user = update.effective_user
                user_info = f"User: {user.id} (@{user.username})"

            # Log detailed error
            logger.error(f"Error details: {context.error}\n{user_info}")

            # Try to notify user if possible
            if update and hasattr(update, 'effective_chat'):
                try:
                    await context.bot.send_message(
                        chat_id=update.effective_chat.id,
                        text="😔 Произошла ошибка. Пожалуйста, попробуйте позже или обратитесь в поддержку."
                    )
                except Exception as e:
                    logger.error(f"Failed to send error message: {e}")

        except Exception as e:
            logger.error(f"Error in error handler: {e}")

    async def on_shutdown(self, app):
        """Cleanup resources on shutdown"""
        try:
            # Close database connection
            if hasattr(self, 'db'):
                await self.db.close()

            # Close payment manager
            if hasattr(self, 'payment_manager'):
                await self.payment_manager.close()

            # Close aiohttp session
            if hasattr(self, 'session') and self.session:
                await self.session.close()

        except Exception as e:
            logger.error(f"Error during shutdown: {e}")


def main():
    """Main function with proper error handling"""
    try:
        # Validate environment
        Config.validate_environment()

        # Initialize bot
        bot = SafeZoneBot()

        # Create application
        app = (
            Application.builder()
            .token(Config.BOT_TOKEN)
            .post_init(bot.initialize)
            .post_shutdown(bot.on_shutdown)
            .build()
        )

        # Add handlers
        app.add_handler(CommandHandler("start", bot.start_command))
        app.add_handler(CommandHandler("help", bot.help_menu))
        app.add_handler(CommandHandler("pricing", bot.show_pricing))
        app.add_handler(CommandHandler("myconfigs", bot.my_configs))
        app.add_handler(CommandHandler("stats", bot.user_stats))
        app.add_handler(CommandHandler("server", bot.server_info))
        app.add_handler(CommandHandler("referral", bot.referral_program))
        app.add_handler(CommandHandler("payment_help", bot.payment_help))
        app.add_handler(CommandHandler("how_to_buy_ton", bot.how_to_buy_ton))

        # Add callback handlers
        app.add_handler(CallbackQueryHandler(bot.create_protocol_config, pattern="^create_"))
        app.add_handler(CallbackQueryHandler(bot.process_payment, pattern="^pay_"))
        app.add_handler(CallbackQueryHandler(bot.check_payment, pattern="^check_"))
        app.add_handler(CallbackQueryHandler(bot.back_to_menu, pattern="^back_"))

        # Add error handler
        app.add_error_handler(bot.error_handler)

        # Add periodic jobs
        app.job_queue.run_repeating(bot._cleanup_expired_config, interval=300)  # Every 5 minutes

        # Run with polling
        app.run_polling(
            drop_pending_updates=True,
            allowed_updates=["message", "callback_query", "chat_member", "my_chat_member"]
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
