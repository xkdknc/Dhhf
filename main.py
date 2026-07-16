import asyncio
import logging
import re
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from contextlib import contextmanager

from aiogram import Bot, Dispatcher, types
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode, ContentType
from aiogram.filters import Command, StateFilter
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import (
    Message, CallbackQuery, ChatMemberUpdated, 
    InlineKeyboardMarkup, InlineKeyboardButton,
    ContentTypes
)
from aiogram.utils.keyboard import InlineKeyboardBuilder
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# ==================== CONFIG ====================
BOT_TOKEN = os.getenv("8810741889:AAEjL5vlgL0mxZeAmRGWtDuU7kKFCKwJQ2M")
ADMIN_IDS = [int(id.strip()) for id in os.getenv("8680457924", "").split(",") if id.strip()]
DB_PATH = os.getenv("DB_PATH", "group_guard.db")
LOG_CHANNEL = int(os.getenv("LOG_CHANNEL", 0)) if os.getenv("LOG_CHANNEL") else None

# ==================== DATABASE ====================
class Database:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_db()
    
    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def init_db(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS groups (
                    chat_id INTEGER PRIMARY KEY,
                    rules TEXT,
                    welcome_message TEXT,
                    antispam_enabled INTEGER DEFAULT 1,
                    antiflood_enabled INTEGER DEFAULT 1,
                    antibots_enabled INTEGER DEFAULT 1,
                    antiforward_enabled INTEGER DEFAULT 1,
                    captcha_enabled INTEGER DEFAULT 1,
                    blacklist_enabled INTEGER DEFAULT 1,
                    log_channel INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blacklist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chat_id INTEGER,
                    word TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(chat_id, word)
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS muted_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chat_id INTEGER,
                    user_id INTEGER,
                    until TIMESTAMP,
                    reason TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chat_id INTEGER,
                    user_id INTEGER,
                    message_id INTEGER,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS pending_captchas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chat_id INTEGER,
                    user_id INTEGER,
                    message_id INTEGER,
                    code TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
    
    def get_group_settings(self, chat_id: int) -> Dict:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM groups WHERE chat_id = ?', (chat_id,))
            row = cursor.fetchone()
            
            if row:
                return dict(row)
            
            cursor.execute('''
                INSERT INTO groups (chat_id) VALUES (?)
            ''', (chat_id,))
            conn.commit()
            
            cursor.execute('SELECT * FROM groups WHERE chat_id = ?', (chat_id,))
            row = cursor.fetchone()
            return dict(row) if row else {}
    
    def update_setting(self, chat_id: int, key: str, value):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f'UPDATE groups SET {key} = ? WHERE chat_id = ?', (value, chat_id))
            conn.commit()
    
    def get_blacklist(self, chat_id: int) -> List[str]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT word FROM blacklist WHERE chat_id = ?', (chat_id,))
            return [row['word'].lower() for row in cursor.fetchall()]
    
    def add_blacklist_word(self, chat_id: int, word: str):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT OR IGNORE INTO blacklist (chat_id, word) VALUES (?, ?)', (chat_id, word.lower()))
            conn.commit()
    
    def remove_blacklist_word(self, chat_id: int, word: str):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM blacklist WHERE chat_id = ? AND word = ?', (chat_id, word.lower()))
            conn.commit()
    
    def add_user_message(self, chat_id: int, user_id: int, message_id: int):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                DELETE FROM user_messages 
                WHERE chat_id = ? AND timestamp < datetime('now', '-30 seconds')
            ''', (chat_id,))
            
            cursor.execute('''
                INSERT INTO user_messages (chat_id, user_id, message_id)
                VALUES (?, ?, ?)
            ''', (chat_id, user_id, message_id))
            conn.commit()
    
    def get_user_message_count(self, chat_id: int, user_id: int, seconds: int = 10) -> int:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT COUNT(*) as count FROM user_messages
                WHERE chat_id = ? AND user_id = ? 
                AND timestamp > datetime('now', ? || ' seconds')
            ''', (chat_id, user_id, f'-{seconds}'))
            return cursor.fetchone()['count']
    
    def add_pending_captcha(self, chat_id: int, user_id: int, message_id: int, code: str):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM pending_captchas WHERE chat_id = ? AND user_id = ?', (chat_id, user_id))
            
            cursor.execute('''
                INSERT INTO pending_captchas (chat_id, user_id, message_id, code)
                VALUES (?, ?, ?, ?)
            ''', (chat_id, user_id, message_id, code))
            conn.commit()
    
    def get_pending_captcha(self, chat_id: int, user_id: int) -> Optional[Dict]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM pending_captchas 
                WHERE chat_id = ? AND user_id = ?
                AND created_at > datetime('now', '-60 seconds')
            ''', (chat_id, user_id))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def remove_pending_captcha(self, chat_id: int, user_id: int):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM pending_captchas WHERE chat_id = ? AND user_id = ?', (chat_id, user_id))
            conn.commit()

# Initialize database
db = Database(DB_PATH)

# ==================== BOT SETUP ====================
storage = MemoryStorage()
bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.MARKDOWN))
dp = Dispatcher(storage=storage)

# ==================== STATES ====================
class AdminStates(StatesGroup):
    SET_RULES = State()
    SET_WELCOME = State()
    ADD_WORD = State()
    DEL_WORD = State()
    SET_LOG_CHANNEL = State()

# ==================== HELPERS ====================
async def is_admin(message: Message) -> bool:
    """Check if user is admin in the group or super admin"""
    if message.from_user.id in ADMIN_IDS:
        return True
    
    chat_member = await bot.get_chat_member(message.chat.id, message.from_user.id)
    return chat_member.status in ['administrator', 'creator']

async def is_bot_admin(chat_id: int) -> bool:
    """Check if bot is admin in the group"""
    bot_member = await bot.get_chat_member(chat_id, bot.id)
    return bot_member.status in ['administrator', 'creator']

async def get_mention(user: types.User) -> str:
    """Get user mention"""
    if user.username:
        return f"@{user.username}"
    return f"[{user.first_name}](tg://user?id={user.id})"

def parse_time(time_str: str) -> Optional[timedelta]:
    """Parse time string like 1h, 30m, 1d"""
    match = re.match(r'(\d+)([smhd])', time_str.lower())
    if not match:
        return None
    
    value = int(match.group(1))
    unit = match.group(2)
    
    if unit == 's':
        return timedelta(seconds=value)
    elif unit == 'm':
        return timedelta(minutes=value)
    elif unit == 'h':
        return timedelta(hours=value)
    elif unit == 'd':
        return timedelta(days=value)
    return None

async def log_event(chat_id: int, event_type: str, message: str):
    """Log event to log channel if set"""
    settings = db.get_group_settings(chat_id)
    log_channel = settings.get('log_channel') or LOG_CHANNEL
    
    if not log_channel:
        return
    
    try:
        log_text = f"""
📋 **Event Log**

**Chat:** {chat_id}
**Type:** {event_type}
**Message:** {message}
**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        await bot.send_message(log_channel, log_text)
    except Exception as e:
        logging.error(f"Failed to log event: {e}")

# ==================== COMMAND HANDLERS ====================

@dp.message(Command('start'))
async def cmd_start(message: Message):
    """Handle /start command"""
    welcome_text = """
🤖 **Group Guard Bot**

I protect your groups from spam, bots, and unwanted behavior!

**Commands for admins:**
/panel - Open admin panel
/status - Show protection status
/setrules - Set group rules
/setwelcome - Set welcome message
/addword - Add word to blacklist
/delword - Remove word from blacklist
/mute @user [time] - Mute a user
/ban @user - Ban a user
/unban @user - Unban a user
/toggleprotection - Toggle protection features
/setlogchannel - Set log channel

**How to use:**
1. Add me to your group
2. Make me admin
3. Use /panel to configure
"""
    await message.reply(welcome_text)

@dp.message(Command('panel'))
async def cmd_panel(message: Message):
    """Handle /panel command"""
    if not await is_admin(message):
        await message.reply("⛔ You don't have permission to use this command.")
        return
    
    settings = db.get_group_settings(message.chat.id)
    
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="📋 Status", callback_data="panel_status"),
            InlineKeyboardButton(text="⚙️ Toggle Protection", callback_data="panel_toggle")
        ],
        [
            InlineKeyboardButton(text="📝 Rules", callback_data="panel_rules"),
            InlineKeyboardButton(text="👋 Welcome", callback_data="panel_welcome")
        ],
        [
            InlineKeyboardButton(text="🚫 Blacklist", callback_data="panel_blacklist"),
            InlineKeyboardButton(text="🔗 Log Channel", callback_data="panel_logchannel")
        ],
        [
            InlineKeyboardButton(text="📊 Stats", callback_data="panel_stats"),
            InlineKeyboardButton(text="🔄 Refresh", callback_data="panel_refresh")
        ]
    ])
    
    status_text = f"""
📊 **Protection Status**

🛡️ Anti-Spam: {'✅' if settings.get('antispam_enabled', 1) else '❌'}
🛡️ Anti-Flood: {'✅' if settings.get('antiflood_enabled', 1) else '❌'}
🛡️ Anti-Bot: {'✅' if settings.get('antibots_enabled', 1) else '❌'}
🛡️ Anti-Forward: {'✅' if settings.get('antiforward_enabled', 1) else '❌'}
🛡️ Captcha: {'✅' if settings.get('captcha_enabled', 1) else '❌'}
🛡️ Blacklist: {'✅' if settings.get('blacklist_enabled', 1) else '❌'}

📝 Rules: {'✅ Set' if settings.get('rules') else '❌ Not set'}
👋 Welcome: {'✅ Set' if settings.get('welcome_message') else '❌ Not set'}
"""
    
    await message.reply(status_text, reply_markup=keyboard)

@dp.message(Command('status'))
async def cmd_status(message: Message):
    """Handle /status command"""
    if not await is_admin(message):
        await message.reply("⛔ You don't have permission to use this command.")
        return
    
    settings = db.get_group_settings(message.chat.id)
    
    status_text = f"""
📊 **Group Protection Status**

🛡️ **Anti-Spam:** {'✅ Active' if settings.get('antispam_enabled', 1) else '❌ Inactive'}
🛡️ **Anti-Flood:** {'✅ Active' if settings.get('antiflood_enabled', 1) else '❌ Inactive'}
🛡️ **Anti-Bot:** {'✅ Active' if settings.get('antibots_enabled', 1) else '❌ Inactive'}
🛡️ **Anti-Forward:** {'✅ Active' if settings.get('antiforward_enabled', 1) else '❌ Inactive'}
🛡️ **Captcha:** {'✅ Active' if settings.get('captcha_enabled', 1) else '❌ Inactive'}
🛡️ **Blacklist:** {'✅ Active' if settings.get('blacklist_enabled', 1) else '❌ Inactive'}

📝 **Rules:** {'Set' if settings.get('rules') else 'Not set'}
👋 **Welcome:** {'Set' if settings.get('welcome_message') else 'Not set'}

🔗 **Log Channel:** {'Set' if settings.get('log_channel') else 'Not set'}
"""
    await message.reply(status_text)

@dp.message(Command('setrules'))
async def cmd_setrules(message: Message, state: FSMContext):
    """Handle /setrules command"""
    if not await is_admin(message):
        await message.reply("⛔ You don't have permission to use this command.")
        return
    
    if message.reply_to_message:
        rules = message.reply_to_message.text or message.reply_to_message.caption
        if rules:
            db.update_setting(message.chat.id, 'rules', rules)
            await message.reply("✅ Rules set successfully!")
            await log_event(message.chat.id, "RULES_UPDATED", f"Rules updated by {message.from_user.id}")
            return
    
    await message.reply("Please send the new rules:")
    await state.set_state(AdminStates.SET_RULES)

@dp.message(StateFilter(AdminStates.SET_RULES))
async def process_setrules(message: Message, state: FSMContext):
    """Process setting rules"""
    db.update_setting(message.chat.id, 'rules', message.text)
    await message.reply("✅ Rules set successfully!")
    await state.clear()
    await log_event(message.chat.id, "RULES_UPDATED", f"Rules updated by {message.from_user.id}")

@dp.message(Command('setwelcome'))
async def cmd_setwelcome(message: Message, state: FSMContext):
    """Handle /setwelcome command"""
    if not await is_admin(message):
        await message.reply("⛔ You don't have permission to use this command.")
        return
    
    if message.reply_to_message:
        welcome = message.reply_to_message.text or message.reply_to_message.caption
        if welcome:
            db.update_setting(message.chat.id, 'welcome_message', welcome)
            await message.reply("✅ Welcome message set successfully!")
            await log_event(message.chat.id, "WELCOME_UPDATED", f"Welcome updated by {message.from_user.id}")
            return
    
    await message.reply("Please send the new welcome message:")
    await state.set_state(AdminStates.SET_WELCOME)

@dp.message(StateFilter(AdminStates.SET_WELCOME))
async def process_setwelcome(message: Message, state: FSMContext):
    """Process setting welcome message"""
    db.update_setting(message.chat.id, 'welcome_message', message.text)
    await message.reply("✅ Welcome message set successfully!")
    await state.clear()
    await log_event(message.chat.id, "WELCOME_UPDATED", f"Welcome updated by {message.from_user.id}")

@dp.message(Command('addword'))
async def cmd_addword(message: Message, state: FSMContext):
    """Handle /addword command"""
    if not await is_admin(message):
        await message.reply("⛔ You don't have permission to use this command.")
        return
    
    args = message.text.split(maxsplit=1)
    if len(args) > 1:
        word = args[1].strip()
        if word:
            db.add_blacklist_word(message.chat.id, word)
            await message.reply(f"✅ Added '{word}' to blacklist!")
            await log_event(message.chat.id, "WORD_ADDED", f"Added '{word}' by {message.from_user.id}")
            return
    
    await message.reply("Please send the word to add to blacklist:")
    await state.set_state(AdminStates.ADD_WORD)

@dp.message(StateFilter(AdminStates.ADD_WORD))
async def process_addword(message: Message, state: FSMContext):
    """Process adding word to blacklist"""
    word = message.text.strip()
    if word:
        db.add_blacklist_word(message.chat.id, word)
        await message.reply(f"✅ Added '{word}' to blacklist!")
        await log_event(message.chat.id, "WORD_ADDED", f"Added '{word}' by {message.from_user.id}")
    await state.clear()

@dp.message(Command('delword'))
async def cmd_delword(message: Message, state: FSMContext):
    """Handle /delword command"""
    if not await is_admin(message):
        await message.reply("⛔ You don't have permission to use this command.")
        return
    
    args = message.text.split(maxsplit=1)
    if len(args) > 1:
        word = args[1].strip()
        if word:
            db.remove_blacklist_word(message.chat.id, word)
            await message.reply(f"✅ Removed '{word}' from blacklist!")
            await log_event(message.chat.id, "WORD_REMOVED", f"Removed '{word}' by {message.from_user.id}")
            return
    
    await message.reply("Please send the word to remove from blacklist:")
    await state.set_state(AdminStates.DEL_WORD)

@dp.message(StateFilter(AdminStates.DEL_WORD))
async def process_delword(message: Message, state: FSMContext):
    """Process removing word from blacklist"""
    word = message.text.strip()
    if word:
        db.remove_blacklist_word(message.chat.id, word)
        await message.reply(f"✅ Removed '{word}' from blacklist!")
        await log_event(message.chat.id, "WORD_REMOVED", f"Removed '{word}' by {message.from_user.id}")
    await state.clear()

@dp.message(Command('mute'))
async def cmd_mute(message: Message):
    """Handle /mute command"""
    if not await is_admin(message):
        await message.reply("⛔ You don't have permission to use this command.")
        return
    
    if not message.reply_to_message:
        await message.reply("Please reply to a user's message to mute them.")
        return
    
    target_user = message.reply_to_message.from_user
    args = message.text.split(maxsplit=1)
    
    time_str = "1h"
    reason = "Muted by admin"
    
    if len(args) > 1:
        parts = args[1].split(maxsplit=1)
        if parts:
            if parse_time(parts[0]):
                time_str = parts[0]
                if len(parts) > 1:
                    reason = parts[1]
            else:
                reason = args[1]
    
    duration = parse_time(time_str)
    if not duration:
        await message.reply("❌ Invalid time format. Use: 1m, 1h, 1d")
        return
    
    until = datetime.now() + duration
    
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO muted_users (chat_id, user_id, until, reason)
            VALUES (?, ?, ?, ?)
        ''', (message.chat.id, target_user.id, until, reason))
        conn.commit()
    
    await message.reply(f"✅ Muted {await get_mention(target_user)} for {time_str}")
    await log_event(message.chat.id, "USER_MUTED", f"Muted {target_user.id} for {time_str}")

@dp.message(Command('ban'))
async def cmd_ban(message: Message):
    """Handle /ban command"""
    if not await is_admin(message):
        await message.reply("⛔ You don't have permission to use this command.")
        return
    
    if not message.reply_to_message:
        await message.reply("Please reply to a user's message to ban them.")
        return
    
    target_user = message.reply_to_message.from_user
    await bot.ban_chat_member(message.chat.id, target_user.id)
    await message.reply(f"✅ Banned {await get_mention(target_user)}")
    await log_event(message.chat.id, "USER_BANNED", f"Banned {target_user.id} by {message.from_user.id}")

@dp.message(Command('unban'))
async def cmd_unban(message: Message):
    """Handle /unban command"""
    if not await is_admin(message):
        await message.reply("⛔ You don't have permission to use this command.")
        return
    
    if not message.reply_to_message:
        await message.reply("Please reply to a user's message to unban them.")
        return
    
    target_user = message.reply_to_message.from_user
    await bot.unban_chat_member(message.chat.id, target_user.id)
    await message.reply(f"✅ Unbanned {await get_mention(target_user)}")
    await log_event(message.chat.id, "USER_UNBANNED", f"Unbanned {target_user.id} by {message.from_user.id}")

@dp.message(Command('toggleprotection'))
async def cmd_toggleprotection(message: Message):
    """Handle /toggleprotection command"""
    if not await is_admin(message):
        await message.reply("⛔ You don't have permission to use this command.")
        return
    
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        await message.reply("Please specify what to toggle:\n/toggleprotection <antispam|antiflood|antibots|antiforward|captcha|blacklist>")
        return
    
    feature = args[1].lower()
    settings = db.get_group_settings(message.chat.id)
    
    mapping = {
        'antispam': 'antispam_enabled',
        'antiflood': 'antiflood_enabled',
        'antibots': 'antibots_enabled',
        'antiforward': 'antiforward_enabled',
        'captcha': 'captcha_enabled',
        'blacklist': 'blacklist_enabled'
    }
    
    if feature not in mapping:
        await message.reply("❌ Unknown feature. Available: antispam, antiflood, antibots, antiforward, captcha, blacklist")
        return
    
    db_key = mapping[feature]
    current = settings.get(db_key, 1)
    new_value = 0 if current else 1
    db.update_setting(message.chat.id, db_key, new_value)
    
    status = "✅ Enabled" if new_value else "❌ Disabled"
    await message.reply(f"{status} {feature}")
    await log_event(message.chat.id, "TOGGLE_PROTECTION", f"{feature} toggled to {new_value} by {message.from_user.id}")

@dp.message(Command('setlogchannel'))
async def cmd_setlogchannel(message: Message):
    """Handle /setlogchannel command"""
    if not await is_admin(message):
        await message.reply("⛔ You don't have permission to use this command.")
        return
    
    if not message.reply_to_message:
        await message.reply("Please reply to a message in the channel you want to set as log channel.")
        return
    
    if message.reply_to_message.forward_from_chat:
        chat_id = message.reply_to_message.forward_from_chat.id
    else:
        chat_id = message.reply_to_message.chat.id
    
    db.update_setting(message.chat.id, 'log_channel', chat_id)
    await message.reply(f"✅ Log channel set to: {chat_id}")
    await log_event(message.chat.id, "LOG_CHANNEL_SET", f"Log channel set to {chat_id} by {message.from_user.id}")

# ==================== GROUP MESSAGE HANDLER ====================

@dp.message()
async def handle_group_messages(message: Message):
    """Handle all group messages"""
    if message.chat.type not in ['group', 'supergroup']:
        return
    
    # Check if bot is admin
    if not await is_bot_admin(message.chat.id):
        return
    
    # Skip admin messages
    if await is_admin(message):
        return
    
    # Skip if no text
    if not message.text:
        return
    
    settings = db.get_group_settings(message.chat.id)
    
    # Check if user is muted
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM muted_users 
            WHERE chat_id = ? AND user_id = ? AND until > datetime('now')
        ''', (message.chat.id, message.from_user.id))
        if cursor.fetchone():
            await message.delete()
            return
    
    # Check antiflood
    if settings.get('antiflood_enabled', 1):
        msg_count = db.get_user_message_count(message.chat.id, message.from_user.id, 5)
        if msg_count > 3:
            await message.delete()
            return
    
    # Check antispam
    if settings.get('antispam_enabled', 1):
        mentions = len(re.findall(r'@\w+', message.text))
        if mentions > 5:
            await message.delete()
            return
        
        emoji_count = len(re.findall(r'[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF\U0001F680-\U0001F6FF\U0001F700-\U0001F77F\U0001F780-\U0001F7FF\U0001F800-\U0001F8FF\U0001F900-\U0001F9FF\U0001FA00-\U0001FA6F\U0001FA70-\U0001FAFF\u2600-\u26FF\u2700-\u27BF\uFE00-\uFE0F]', message.text))
        if emoji_count > 10:
            await message.delete()
            return
    
    # Check blacklist
    if settings.get('blacklist_enabled', 1):
        blacklist = db.get_blacklist(message.chat.id)
        text_lower = message.text.lower()
        for word in blacklist:
            if word in text_lower:
                await message.delete()
                return
    
    # Check antiforward
    if settings.get('antiforward_enabled', 1) and message.forward_from:
        await message.delete()
        return
    
    # Record message for flood control
    db.add_user_message(message.chat.id, message.from_user.id, message.message_id)

# ==================== NEW MEMBER HANDLER ====================

@dp.message()
async def handle_new_members(message: Message):
    """Handle new members joining"""
    if not message.new_chat_members:
        return
    
    if message.chat.type not in ['group', 'supergroup']:
        return
    
    if not await is_bot_admin(message.chat.id):
        return
    
    settings = db.get_group_settings(message.chat.id)
    
    for new_member in message.new_chat_members:
        if new_member.is_bot:
            if settings.get('antibots_enabled', 1):
                await bot.ban_chat_member(message.chat.id, new_member.id)
                await message.reply(f"🤖 Bot {await get_mention(new_member)} kicked!")
                await log_event(message.chat.id, "BOT_KICKED", f"Kicked bot {new_member.id}")
            continue
        
        if settings.get('welcome_message'):
            welcome = settings['welcome_message'].replace('{user}', await get_mention(new_member))
            await message.reply(welcome)
        
        if settings.get('captcha_enabled', 1):
            import random
            code = str(random.randint(1000, 9999))
            
            keyboard = InlineKeyboardMarkup(inline_keyboard=[])
            row = []
            for i in range(10):
                row.append(InlineKeyboardButton(str(i), callback_data=f"captcha_{i}"))
                if len(row) == 5:
                    keyboard.inline_keyboard.append(row.copy())
                    row = []
            if row:
                keyboard.inline_keyboard.append(row)
            
            msg = await message.reply(
                f"🔐 {await get_mention(new_member)}, please type the code: `{code}`\nYou have 60 seconds!"
            )
            
            db.add_pending_captcha(message.chat.id, new_member.id, msg.message_id, code)
            
            await asyncio.sleep(60)
            pending = db.get_pending_captcha(message.chat.id, new_member.id)
            if pending:
                await bot.ban_chat_member(message.chat.id, new_member.id)
                await message.reply(f"⏰ {await get_mention(new_member)} kicked - captcha timeout!")
                await log_event(message.chat.id, "CAPTCHA_FAILED", f"Captcha timeout for {new_member.id}")

# ==================== CAPTCHA HANDLER ====================

@dp.callback_query(lambda c: c.data.startswith('captcha_'))
async def process_captcha_callback(callback_query: CallbackQuery):
    """Process captcha callback"""
    user_id = callback_query.from_user.id
    chat_id = callback_query.message.chat.id
    
    pending = db.get_pending_captcha(chat_id, user_id)
    if not pending:
        await callback_query.answer("❌ No pending captcha!")
        return
    
    code = callback_query.data.split('_')[1]
    
    if code == pending['code']:
        db.remove_pending_captcha(chat_id, user_id)
        await callback_query.message.edit_text("✅ Captcha verified! Welcome to the group!")
        await callback_query.answer("✅ Verified!")
        await log_event(chat_id, "CAPTCHA_PASSED", f"User {user_id} passed captcha")
    else:
        await callback_query.answer("❌ Wrong code!", show_alert=True)

# ==================== CAPTCHA MESSAGE HANDLER ====================

@dp.message()
async def handle_captcha_input(message: Message):
    """Handle captcha code input"""
    if message.chat.type not in ['group', 'supergroup']:
        return
    
    if not message.text:
        return
    
    pending = db.get_pending_captcha(message.chat.id, message.from_user.id)
    if not pending:
        return
    
    if message.text == pending['code']:
        db.remove_pending_captcha(message.chat.id, message.from_user.id)
        await message.delete()
        await bot.send_message(message.chat.id, f"✅ {await get_mention(message.from_user)} verified! Welcome!")
        await log_event(message.chat.id, "CAPTCHA_PASSED", f"User {message.from_user.id} passed captcha")

# ==================== CHAT MEMBER UPDATE ====================

@dp.chat_member()
async def chat_member_update(chat_member_update: ChatMemberUpdated):
    """Handle chat member updates"""
    if chat_member_update.chat.type not in ['group', 'supergroup']:
        return
    
    if chat_member_update.new_chat_member.user.id == bot.id:
        if chat_member_update.new_chat_member.status == 'member':
            await bot.send_message(chat_member_update.chat.id, "👋 Thanks for adding me! I need admin permissions to work properly.")
    
    if chat_member_update.old_chat_member.status in ['administrator', 'member'] and chat_member_update.new_chat_member.status == 'left':
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM muted_users WHERE chat_id = ? AND user_id = ?', 
                         (chat_member_update.chat.id, chat_member_update.old_chat_member.user.id))
            conn.commit()

# ==================== PANEL CALLBACKS ====================

@dp.callback_query(lambda c: c.data.startswith('panel_'))
async def handle_panel_callbacks(callback_query: CallbackQuery):
    """Handle panel callbacks"""
    await callback_query.answer()
    
    action = callback_query.data.split('_', 1)[1]
    chat_id = callback_query.message.chat.id
    
    if action == 'status':
        settings = db.get_group_settings(chat_id)
        text = f"""
📊 **Protection Status**

🛡️ Anti-Spam: {'✅' if settings.get('antispam_enabled', 1) else '❌'}
🛡️ Anti-Flood: {'✅' if settings.get('antiflood_enabled', 1) else '❌'}
🛡️ Anti-Bot: {'✅' if settings.get('antibots_enabled', 1) else '❌'}
🛡️ Anti-Forward: {'✅' if settings.get('antiforward_enabled', 1) else '❌'}
🛡️ Captcha: {'✅' if settings.get('captcha_enabled', 1) else '❌'}
🛡️ Blacklist: {'✅' if settings.get('blacklist_enabled', 1) else '❌'}
"""
        await callback_query.message.edit_text(text)
    
    elif action == 'toggle':
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(text=f"{'✅' if settings.get('antispam_enabled', 1) else '❌'} Anti-Spam", callback_data="toggle_antispam"),
                InlineKeyboardButton(text=f"{'✅' if settings.get('antiflood_enabled', 1) else '❌'} Anti-Flood", callback_data="toggle_antiflood")
            ],
            [
                InlineKeyboardButton(text=f"{'✅' if settings.get('antibots_enabled', 1) else '❌'} Anti-Bot", callback_data="toggle_antibots"),
                InlineKeyboardButton(text=f"{'✅' if settings.get('antiforward_enabled', 1) else '❌'} Anti-Forward", callback_data="toggle_antiforward")
            ],
            [
                InlineKeyboardButton(text=f"{'✅' if settings.get('captcha_enabled', 1) else '❌'} Captcha", callback_data="toggle_captcha"),
                InlineKeyboardButton(text=f"{'✅' if settings.get('blacklist_enabled', 1) else '❌'} Blacklist", callback_data="toggle_blacklist")
            ],
            [
                InlineKeyboardButton(text="🔙 Back", callback_data="panel_refresh")
            ]
        ])
        
        await callback_query.message.edit_text("⚙️ Click to toggle features:", reply_markup=keyboard)
    
    elif action == 'rules':
        settings = db.get_group_settings(chat_id)
        rules = settings.get('rules', 'No rules set yet.')
        await callback_query.message.edit_text(f"📝 **Rules:**\n\n{rules}")
    
    elif action == 'welcome':
        settings = db.get_group_settings(chat_id)
        welcome = settings.get('welcome_message', 'No welcome message set yet.')
        await callback_query.message.edit_text(f"👋 **Welcome Message:**\n\n{welcome}")
    
    elif action == 'blacklist':
        blacklist = db.get_blacklist(chat_id)
        if blacklist:
            text = "🚫 **Blacklisted Words:**\n\n" + "\n".join([f"• {word}" for word in blacklist])
        else:
            text = "🚫 **Blacklist is empty**"
        await callback_query.message.edit_text(text)
    
    elif action == 'stats':
        await callback_query.message.edit_text("📊 **Statistics coming soon...**")
    
    elif action == 'logchannel':
        settings = db.get_group_settings(chat_id)
        log_channel = settings.get('log_channel')
        if log_channel:
            await callback_query.message.edit_text(f"🔗 **Log Channel:** {log_channel}")
        else:
            await callback_query.message.edit_text("🔗 **Log Channel:** Not set")
    
    elif action == 'refresh':
        await cmd_panel(callback_query.message)

@dp.callback_query(lambda c: c.data.startswith('toggle_'))
async def handle_toggle_callbacks(callback_query: CallbackQuery):
    """Handle toggle callbacks from panel"""
    await callback_query.answer()
    
    feature = callback_query.data.split('_', 1)[1]
    chat_id = callback_query.message.chat.id
    
    mapping = {
        'antispam': 'antispam_enabled',
        'antiflood': 'antiflood_enabled',
        'antibots': 'antibots_enabled',
        'antiforward': 'antiforward_enabled',
        'captcha': 'captcha_enabled',
        'blacklist': 'blacklist_enabled'
    }
    
    if feature not in mapping:
        return
    
    settings = db.get_group_settings(chat_id)
    db_key = mapping[feature]
    current = settings.get(db_key, 1)
    new_value = 0 if current else 1
    db.update_setting(chat_id, db_key, new_value)
    
    await callback_query.answer(f"✅ {feature} {'enabled' if new_value else 'disabled'}")
    await handle_panel_callbacks(callback_query)

# ==================== ERROR HANDLER ====================

@dp.error()
async def errors_handler(update, exception):
    """Handle errors"""
    error_text = f"⚠️ Error: {exception}"
    logging.error(error_text)
    
    try:
        if LOG_CHANNEL:
            await bot.send_message(LOG_CHANNEL, f"❌ **Error:**\n{error_text}")
    except:
        pass
    
    return True

# ==================== MAIN ====================

async def on_startup():
    """Called when bot starts"""
    print("🤖 Group Guard Bot started!")
    print(f"👤 Admin IDs: {ADMIN_IDS}")
    print(f"💾 Database: {DB_PATH}")
    if LOG_CHANNEL:
        print(f"📋 Log Channel: {LOG_CHANNEL}")
    
    bot_info = await bot.get_me()
    print(f"🤖 Bot: @{bot_info.username}")
    
    if LOG_CHANNEL:
        await bot.send_message(LOG_CHANNEL, "✅ Bot started successfully!")

async def on_shutdown():
    """Called when bot shuts down"""
    print("🤖 Group Guard Bot stopped!")

async def main():
    """Main entry point"""
    logging.basicConfig(level=logging.INFO)
    
    dp.startup.register(on_startup)
    dp.shutdown.register(on_shutdown)
    
    try:
        await dp.start_polling(bot)
    finally:
        await bot.session.close()

if __name__ == '__main__':
    asyncio.run(main())
