"""ZovPatron — dumper bot (aiogram 3.x). Everything runs through inline buttons."""
from __future__ import annotations

import asyncio
import html
import logging
import os
import shutil
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import aiohttp
import aiosqlite
from aiogram import BaseMiddleware, Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.client.telegram import TelegramAPIServer
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramBadRequest
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import BotCommand, CallbackQuery, FSInputFile, InlineKeyboardButton, Message
from aiogram.utils.keyboard import InlineKeyboardBuilder

import dumper

# ---- config ---------------------------------------------------------------
BOT_TOKEN = os.getenv("BOT_TOKEN", "FILL_BOT_TOKEN")             # FILL: @BotFather
CRYPTO_TOKEN = os.getenv("CRYPTO_TOKEN", "FILL_CRYPTO_TOKEN")    # FILL: @CryptoBot -> Crypto Pay -> Create App
ADMIN_IDS = {int(x) for x in os.getenv("ADMIN_IDS", "0").split(",") if x.strip()}  # FILL: your tg id(s)
LOCAL_API = os.getenv("LOCAL_API", "")                           # http://127.0.0.1:8081 (needed for >20 MB files)
CRYPTO_API = os.getenv("CRYPTO_API", "https://pay.crypt.bot/api")  # testnet: https://testnet-pay.crypt.bot/api
DB_PATH = os.getenv("DB_PATH", "zovpatron.db")
PRICE_USD = 1
SUB_DAYS = 30
MAX_MB = 200
MAX_PARALLEL = 2

MB = 1024 * 1024
CLOUD_DL_MB = 20          # cloud Bot API: download limit
CLOUD_UP_MB = 49          # cloud Bot API: upload limit
LOCAL_UP_MB = 1990
LINE = "━━━━━━━━━━━━━━━━━━"

log = logging.getLogger("zovpatron")
SEM = asyncio.Semaphore(MAX_PARALLEL)
BUSY: set[int] = set()


def now() -> int:
    return int(time.time())


def fdate(ts: int) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%d.%m.%Y")


# ---- db -------------------------------------------------------------------
class DB:
    def __init__(self, path: str) -> None:
        self.path = path
        self.c: aiosqlite.Connection

    async def init(self) -> None:
        self.c = await aiosqlite.connect(self.path)
        self.c.row_factory = aiosqlite.Row
        await self.c.executescript("""
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY, name TEXT, joined INTEGER,
                sub_until INTEGER DEFAULT 0, dumps INTEGER DEFAULT 0, banned INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS payments(
                invoice_id INTEGER PRIMARY KEY, user_id INTEGER, amount REAL, status TEXT, created INTEGER);
        """)
        await self.c.commit()

    async def one(self, sql: str, a: tuple = ()):
        cur = await self.c.execute(sql, a)
        return await cur.fetchone()

    async def all(self, sql: str, a: tuple = ()):
        cur = await self.c.execute(sql, a)
        return await cur.fetchall()

    async def run(self, sql: str, a: tuple = ()) -> int:
        cur = await self.c.execute(sql, a)
        await self.c.commit()
        return cur.rowcount

    async def touch(self, uid: int, name: str = "") -> None:
        await self.c.execute("INSERT OR IGNORE INTO users(id,name,joined) VALUES(?,?,?)", (uid, name, now()))
        if name:
            await self.c.execute("UPDATE users SET name=? WHERE id=?", (name, uid))
        await self.c.commit()

    async def user(self, uid: int):
        await self.touch(uid)
        return await self.one("SELECT * FROM users WHERE id=?", (uid,))

    async def add_sub(self, uid: int, days: int) -> int:
        row = await self.user(uid)
        until = max(row["sub_until"], now()) + days * 86400
        await self.run("UPDATE users SET sub_until=? WHERE id=?", (until, uid))
        return until


db = DB(DB_PATH)


def can_exe(row, uid: int) -> bool:
    return uid in ADMIN_IDS or row["sub_until"] > now()


# ---- cryptobot ------------------------------------------------------------
async def crypto(method: str, **params):
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as s:
        async with s.post(f"{CRYPTO_API}/{method}", json=params,
                          headers={"Crypto-Pay-API-Token": CRYPTO_TOKEN}) as r:
            j = await r.json()
    if not j.get("ok"):
        raise RuntimeError(j)
    return j["result"]


# ---- ui helpers -----------------------------------------------------------
def btn(text: str, data: str | None = None, url: str | None = None) -> InlineKeyboardButton:
    return InlineKeyboardButton(text=text, callback_data=data, url=url)


def kb(*rows: list[InlineKeyboardButton]):
    b = InlineKeyboardBuilder()
    for row in rows:
        b.row(*row)
    return b.as_markup()


BACK = kb([btn("⬅️ Назад", "menu")])


async def show(ev: Message | CallbackQuery, text: str, markup=None) -> None:
    if isinstance(ev, CallbackQuery):
        try:
            await ev.message.edit_text(text, reply_markup=markup)
            return
        except TelegramBadRequest as e:
            if "not modified" in str(e):
                return
        await ev.message.answer(text, reply_markup=markup)
    else:
        await ev.answer(text, reply_markup=markup)


def menu_text(row) -> str:
    sub = row["sub_until"] > now()
    status = f"💎 Подписка до <b>{fdate(row['sub_until'])}</b>" if sub else "🔒 Подписка не активна"
    return (f"🦍 <b>ZovPatron</b>\n{LINE}\n"
            "Приветствую вас! Это дампер <b>«ZovPatron»</b>.\n"
            "Он умеет дампить библиотеки APK-приложений и т.д.\n\n"
            f"{status}\n{LINE}\n<i>выбери действие ниже</i> 👇")


def main_kb(row, uid: int):
    top = [btn("📦 Начать дамп (APK)", "dump_apk")]
    if can_exe(row, uid):
        top.append(btn("🖥 Начать дамп (EXE)", "dump_exe"))
    rows = [top, [btn("💎 Подписки", "subs"), btn("👤 Профиль", "profile")]]
    if uid in ADMIN_IDS:
        rows.append([btn("🛠 Админ-панель", "adm")])
    return kb(*rows)


async def send_menu(ev: Message | CallbackQuery, uid: int) -> None:
    row = await db.user(uid)
    await show(ev, menu_text(row), main_kb(row, uid))


class St(StatesGroup):
    apk = State()
    exe = State()
    meta = State()


class Adm(StatesGroup):
    give = State()
    take = State()
    ban = State()
    unban = State()
    cast = State()


async def reset(state: FSMContext) -> None:
    data = await state.get_data()
    if data.get("work"):
        shutil.rmtree(data["work"], ignore_errors=True)
    await state.clear()


class Gate(BaseMiddleware):
    async def __call__(self, handler, event, data):
        u = event.from_user
        if u:
            await db.touch(u.id, u.username or u.full_name)
            row = await db.user(u.id)
            if row["banned"] and u.id not in ADMIN_IDS:
                if isinstance(event, CallbackQuery):
                    await event.answer("⛔ доступ закрыт", show_alert=True)
                else:
                    await event.answer("⛔ доступ закрыт")
                return
        return await handler(event, data)


r = Router()
adm = Router()
adm.message.filter(F.from_user.id.in_(ADMIN_IDS))
adm.callback_query.filter(F.from_user.id.in_(ADMIN_IDS))


# ---- main menu ------------------------------------------------------------
@r.message(CommandStart())
@r.message(Command("menu"))
async def cmd_start(m: Message, state: FSMContext):
    await reset(state)
    await send_menu(m, m.from_user.id)


@r.callback_query(F.data == "menu")
async def c_menu(cb: CallbackQuery, state: FSMContext):
    await reset(state)
    await send_menu(cb, cb.from_user.id)
    await cb.answer()


@r.callback_query(F.data == "profile")
async def c_profile(cb: CallbackQuery):
    uid = cb.from_user.id
    row = await db.user(uid)
    sub = row["sub_until"] > now()
    await show(cb,
               f"👤 <b>Профиль</b>\n{LINE}\n"
               f"{'👑 <b>Admin</b>' if uid in ADMIN_IDS else '🙂 <b>User</b>'}\n"
               f"🆔 ID: <code>{uid}</code>\n"
               f"📊 Дампов: <b>{row['dumps']}</b>\n"
               f"💎 Подписка: <b>{'до ' + fdate(row['sub_until']) if sub else 'нет'}</b>",
               BACK)
    await cb.answer()


# ---- subscriptions --------------------------------------------------------
@r.callback_query(F.data == "subs")
async def c_subs(cb: CallbackQuery):
    uid = cb.from_user.id
    row = await db.user(uid)
    sub = row["sub_until"] > now()
    pend = await db.one("SELECT invoice_id FROM payments WHERE user_id=? AND status='pending' "
                        "ORDER BY created DESC LIMIT 1", (uid,))
    rows = [[btn(f"🛒 Купить подписку на 1 месяц — {PRICE_USD}$", "buy")]]
    if pend:
        rows.append([btn("🔄 Проверить оплату", f"check:{pend['invoice_id']}")])
    rows.append([btn("⬅️ Назад", "menu")])
    await show(cb,
               f"💎 <b>Подписки</b>\n{LINE}\n"
               "Подписка открывает дамп <b>EXE</b> файлов.\n\n"
               f"⏳ Срок: <b>1 месяц</b>\n💰 Стоимость: <b>{PRICE_USD}$</b>\n💳 Оплата: <b>CryptoBot</b>\n\n"
               f"Статус: <b>{'активна до ' + fdate(row['sub_until']) if sub else 'не активна'}</b>",
               kb(*rows))
    await cb.answer()


@r.callback_query(F.data == "buy")
async def c_buy(cb: CallbackQuery):
    uid = cb.from_user.id
    try:
        inv = await crypto("createInvoice", currency_type="fiat", fiat="USD", amount=str(PRICE_USD),
                           accepted_assets="USDT,TON,BTC,ETH,LTC,TRX",
                           description="ZovPatron — подписка на 1 месяц",
                           payload=str(uid), expires_in=3600, allow_comments=False)
    except Exception:
        log.exception("createInvoice failed")
        return await cb.answer("⚠️ CryptoBot недоступен, попробуй позже", show_alert=True)
    await db.run("INSERT OR REPLACE INTO payments VALUES(?,?,?,?,?)",
                 (inv["invoice_id"], uid, PRICE_USD, "pending", now()))
    url = inv.get("bot_invoice_url") or inv.get("pay_url")
    await show(cb,
               f"🧾 <b>Счёт создан</b>\n{LINE}\n"
               f"Сумма: <b>{PRICE_USD}$</b> · Способ: <b>CryptoBot</b>\n"
               "Счёт действует 1 час.\n\n"
               "1️⃣ нажми <b>Оплатить</b>\n2️⃣ после оплаты нажми <b>Проверить оплату</b>",
               kb([btn("💳 Оплатить", url=url)],
                  [btn("🔄 Проверить оплату", f"check:{inv['invoice_id']}")],
                  [btn("⬅️ Назад", "subs")]))
    await cb.answer()


@r.callback_query(F.data.startswith("check:"))
async def c_check(cb: CallbackQuery):
    uid = cb.from_user.id
    inv_id = int(cb.data.split(":")[1])
    p = await db.one("SELECT * FROM payments WHERE invoice_id=? AND user_id=?", (inv_id, uid))
    if not p:
        return await cb.answer("счёт не найден", show_alert=True)
    if p["status"] == "paid":
        return await cb.answer("этот счёт уже оплачен ✅", show_alert=True)
    try:
        res = await crypto("getInvoices", invoice_ids=str(inv_id))
    except Exception:
        log.exception("getInvoices failed")
        return await cb.answer("⚠️ CryptoBot не отвечает, попробуй позже", show_alert=True)
    items = res["items"] if isinstance(res, dict) else res
    status = items[0]["status"] if items else "unknown"
    if status == "paid":
        if await db.run("UPDATE payments SET status='paid' WHERE invoice_id=? AND status!='paid'", (inv_id,)):
            until = await db.add_sub(uid, SUB_DAYS)
        else:
            until = (await db.user(uid))["sub_until"]
        row = await db.user(uid)
        await show(cb, f"🎉 <b>Оплата получена!</b>\n{LINE}\n"
                       f"💎 Подписка активна до <b>{fdate(until)}</b>\n"
                       "Теперь доступен <b>дамп EXE</b> 🖥", main_kb(row, uid))
        await cb.answer()
    elif status == "expired":
        await db.run("UPDATE payments SET status='expired' WHERE invoice_id=?", (inv_id,))
        await cb.answer("⌛ счёт истёк, создай новый", show_alert=True)
    else:
        await cb.answer("❌ оплата не найдена. Оплати счёт и нажми ещё раз", show_alert=True)


# ---- dumping --------------------------------------------------------------
@r.callback_query(F.data == "dump_apk")
async def c_apk(cb: CallbackQuery, state: FSMContext):
    await reset(state)
    await state.set_state(St.apk)
    cap = MAX_MB if LOCAL_API else CLOUD_DL_MB
    await show(cb, f"📦 <b>Дамп APK</b>\n{LINE}\n"
                   f"Скинь либу до <b>{cap} МБ</b>.\n\n"
                   "Подходит: <code>.apk</code> · <code>.xapk</code> · <code>.zip</code> · <code>.so</code>\n"
                   "После дампа пришлю <b>zip</b>: <code>dump.cs</code> и всё остальное.", BACK)
    await cb.answer()


@r.callback_query(F.data == "dump_exe")
async def c_exe(cb: CallbackQuery, state: FSMContext):
    uid = cb.from_user.id
    if not can_exe(await db.user(uid), uid):
        await cb.answer("🔒 нужна подписка", show_alert=True)
        return await c_subs(cb)
    await reset(state)
    await state.set_state(St.exe)
    cap = MAX_MB if LOCAL_API else CLOUD_DL_MB
    await show(cb, f"🖥 <b>Дамп EXE</b>\n{LINE}\n"
                   f"Скинь файл до <b>{cap} МБ</b>.\n\n"
                   "Подходит: <code>.exe</code> · <code>.dll</code> · <code>.zip</code> (папка игры)\n"
                   "Unity IL2CPP / Mono / .NET / native — метод выберу сам.", BACK)
    await cb.answer()


async def fetch(bot: Bot, file_id: str, dst: Path) -> None:
    f = await bot.get_file(file_id)
    if LOCAL_API and f.file_path and os.path.isabs(f.file_path) and os.path.exists(f.file_path):
        await asyncio.to_thread(shutil.copyfile, f.file_path, dst)
    else:
        await bot.download_file(f.file_path, destination=dst)


async def execute(m: Message, bot: Bot, mode: str, work: Path, src: Path,
                  meta: Path | None, st: Message) -> str:
    """-> 'done' | 'need_meta' | 'fail'"""
    uid = m.from_user.id
    try:
        await st.edit_text("🔬 <b>Дампаю…</b>\n<i>это может занять пару минут</i>")
        async with SEM:
            out, rep = await dumper.dump(src, work, mode, meta)
        zp = work / f"ZovPatron_{src.stem[:40]}_{now()}.zip"
        limit = (LOCAL_UP_MB if LOCAL_API else CLOUD_UP_MB) * MB
        size, light = await asyncio.to_thread(dumper.make_zip, out, zp, limit)
        await st.edit_text("📤 <b>Отправляю архив…</b>")
        await m.answer_document(
            FSInputFile(zp),
            caption=(f"✅ <b>Дамп готов</b>\n{LINE}\n🧬 {html.escape(rep)}\n📦 {size / MB:.1f} МБ"
                     + ("\n<i>архив облегчён (без DummyDll) — лимит Telegram</i>" if light else "")),
            reply_markup=BACK)
        await db.run("UPDATE users SET dumps=dumps+1 WHERE id=?", (uid,))
        await st.delete()
        return "done"
    except dumper.NeedMeta:
        await st.edit_text("🧩 <b>Это IL2CPP-бинарь.</b>\nТеперь скинь <code>global-metadata.dat</code>", reply_markup=BACK)
        return "need_meta"
    except dumper.DumpError as e:
        await st.edit_text(f"❌ <b>Не получилось</b>\n<code>{html.escape(str(e))}</code>", reply_markup=BACK)
    except Exception:
        log.exception("dump crashed")
        await st.edit_text("❌ внутренняя ошибка, попробуй другой файл", reply_markup=BACK)
    return "fail"


async def ingest(m: Message, state: FSMContext, bot: Bot, mode: str) -> None:
    uid = m.from_user.id
    if mode == "exe" and not can_exe(await db.user(uid), uid):
        return await m.answer("🔒 нужна подписка", reply_markup=BACK)
    if uid in BUSY:
        return await m.answer("⏳ у тебя уже идёт дамп, дождись")
    d = m.document
    cap = MAX_MB if LOCAL_API else CLOUD_DL_MB
    if d.file_size and d.file_size > cap * MB:
        return await m.answer(f"❌ файл больше {cap} МБ", reply_markup=BACK)
    BUSY.add(uid)
    work = Path(tempfile.mkdtemp(prefix=f"zp{uid}_"))
    keep = False
    try:
        st = await m.answer("⏬ <b>Скачиваю файл…</b>")
        src = work / dumper.safe_name(d.file_name or "input.bin")
        try:
            await fetch(bot, d.file_id, src)
        except Exception:
            log.exception("download failed")
            return await st.edit_text("❌ не смог скачать файл", reply_markup=BACK)
        res = await execute(m, bot, mode, work, src, None, st)
        if res == "need_meta":
            keep = True
            await state.set_state(St.meta)
            await state.update_data(work=str(work), src=str(src), mode=mode)
    finally:
        BUSY.discard(uid)
        if not keep:
            shutil.rmtree(work, ignore_errors=True)


@r.message(St.apk, F.document)
async def m_apk(m: Message, state: FSMContext, bot: Bot):
    await ingest(m, state, bot, "apk")


@r.message(St.exe, F.document)
async def m_exe(m: Message, state: FSMContext, bot: Bot):
    await ingest(m, state, bot, "exe")


@r.message(St.meta, F.document)
async def m_meta(m: Message, state: FSMContext, bot: Bot):
    data = await state.get_data()
    work, src, mode = Path(data["work"]), Path(data["src"]), data["mode"]
    if not (m.document.file_name or "").lower().endswith(".dat"):
        return await m.answer("нужен файл <code>global-metadata.dat</code>", reply_markup=BACK)
    uid = m.from_user.id
    if uid in BUSY:
        return await m.answer("⏳ дамп уже идёт")
    BUSY.add(uid)
    try:
        st = await m.answer("⏬ <b>Скачиваю metadata…</b>")
        meta = work / "global-metadata.dat"
        try:
            await fetch(bot, m.document.file_id, meta)
        except Exception:
            log.exception("meta download failed")
            return await st.edit_text("❌ не смог скачать файл", reply_markup=BACK)
        await execute(m, bot, mode, work, src, meta, st)
    finally:
        BUSY.discard(uid)
        shutil.rmtree(work, ignore_errors=True)
        await state.clear()
        await state.set_state(St.apk if mode == "apk" else St.exe)


@r.message(St.apk)
@r.message(St.exe)
@r.message(St.meta)
async def m_hint(m: Message):
    await m.answer("📎 пришли <b>файлом</b> (как документ), не текстом", reply_markup=BACK)


# ---- admin ----------------------------------------------------------------
async def adm_panel_text() -> str:
    users = (await db.one("SELECT COUNT(*) c FROM users"))["c"]
    subs = (await db.one("SELECT COUNT(*) c FROM users WHERE sub_until>?", (now(),)))["c"]
    dumps = (await db.one("SELECT COALESCE(SUM(dumps),0) c FROM users"))["c"]
    paid = (await db.one("SELECT COUNT(*) c FROM payments WHERE status='paid'"))["c"]
    return (f"🛠 <b>Админ-панель</b>\n{LINE}\n"
            f"👥 Пользователей: <b>{users}</b>\n💎 Активных подписок: <b>{subs}</b>\n"
            f"📊 Дампов всего: <b>{dumps}</b>\n💰 Оплат: <b>{paid}</b> (~{paid * PRICE_USD}$)")


ADM_KB = kb(
    [btn("👥 Пользователи", "adm_users")],
    [btn("➕ Выдать подписку", "adm_give"), btn("➖ Забрать", "adm_take")],
    [btn("🚫 Бан", "adm_ban"), btn("✅ Разбан", "adm_unban")],
    [btn("📢 Рассылка", "adm_cast")],
    [btn("⬅️ В меню", "menu")],
)
ADM_BACK = kb([btn("⬅️ Админ-панель", "adm")])


@adm.message(Command("admin"))
async def cmd_admin(m: Message, state: FSMContext):
    await reset(state)
    await m.answer(await adm_panel_text(), reply_markup=ADM_KB)


@adm.callback_query(F.data == "adm")
async def c_adm(cb: CallbackQuery, state: FSMContext):
    await reset(state)
    await show(cb, await adm_panel_text(), ADM_KB)
    await cb.answer()


@adm.callback_query(F.data == "adm_users")
async def c_users(cb: CallbackQuery):
    rows = await db.all("SELECT * FROM users ORDER BY joined DESC LIMIT 15")
    lines = []
    for u in rows:
        flag = "🚫" if u["banned"] else ("💎" if u["sub_until"] > now() else "▫️")
        lines.append(f"{flag} <code>{u['id']}</code> {html.escape(u['name'] or '-')} · дампов {u['dumps']}")
    await show(cb, f"👥 <b>Последние 15</b>\n{LINE}\n" + "\n".join(lines), ADM_BACK)
    await cb.answer()


PROMPTS = {
    "give": (Adm.give, "➕ Пришли: <code>ID дни</code>\nнапример <code>123456789 30</code>"),
    "take": (Adm.take, "➖ Пришли <code>ID</code> — снять подписку"),
    "ban": (Adm.ban, "🚫 Пришли <code>ID</code> — забанить"),
    "unban": (Adm.unban, "✅ Пришли <code>ID</code> — разбанить"),
    "cast": (Adm.cast, "📢 Пришли сообщение для рассылки (текст / фото / файл)"),
}


@adm.callback_query(F.data.startswith("adm_") & F.data.func(lambda d: d[4:] in PROMPTS))
async def c_prompt(cb: CallbackQuery, state: FSMContext):
    st, text = PROMPTS[cb.data[4:]]
    await state.set_state(st)
    await show(cb, text, ADM_BACK)
    await cb.answer()


def _ids(text: str) -> list[int] | None:
    try:
        return [int(x) for x in (text or "").split()]
    except ValueError:
        return None


@adm.message(Adm.give)
async def m_give(m: Message, state: FSMContext, bot: Bot):
    a = _ids(m.text)
    if not a:
        return await m.answer("формат: <code>ID дни</code>", reply_markup=ADM_BACK)
    uid, days = a[0], (a[1] if len(a) > 1 else SUB_DAYS)
    until = await db.add_sub(uid, days)
    await state.clear()
    await m.answer(f"✅ <code>{uid}</code>: подписка до <b>{fdate(until)}</b>", reply_markup=ADM_BACK)
    try:
        await bot.send_message(uid, f"🎁 Тебе выдана подписка до <b>{fdate(until)}</b>. Жми /menu")
    except Exception:
        pass


@adm.message(Adm.take)
async def m_take(m: Message, state: FSMContext):
    a = _ids(m.text)
    if not a:
        return await m.answer("пришли числовой ID", reply_markup=ADM_BACK)
    await db.run("UPDATE users SET sub_until=0 WHERE id=?", (a[0],))
    await state.clear()
    await m.answer(f"✅ <code>{a[0]}</code>: подписка снята", reply_markup=ADM_BACK)


@adm.message(Adm.ban)
async def m_ban(m: Message, state: FSMContext):
    a = _ids(m.text)
    if not a:
        return await m.answer("пришли числовой ID", reply_markup=ADM_BACK)
    await db.touch(a[0])
    await db.run("UPDATE users SET banned=1 WHERE id=?", (a[0],))
    await state.clear()
    await m.answer(f"🚫 <code>{a[0]}</code> забанен", reply_markup=ADM_BACK)


@adm.message(Adm.unban)
async def m_unban(m: Message, state: FSMContext):
    a = _ids(m.text)
    if not a:
        return await m.answer("пришли числовой ID", reply_markup=ADM_BACK)
    await db.run("UPDATE users SET banned=0 WHERE id=?", (a[0],))
    await state.clear()
    await m.answer(f"✅ <code>{a[0]}</code> разбанен", reply_markup=ADM_BACK)


@adm.message(Adm.cast)
async def m_cast(m: Message, state: FSMContext):
    await state.clear()
    ids = [x["id"] for x in await db.all("SELECT id FROM users WHERE banned=0")]
    st = await m.answer(f"📢 Рассылаю на {len(ids)}…")
    ok = 0
    for i in ids:
        try:
            await m.copy_to(i)
            ok += 1
        except Exception:
            pass
        await asyncio.sleep(0.05)
    await st.edit_text(f"📢 Доставлено <b>{ok}/{len(ids)}</b>", reply_markup=ADM_BACK)


# ---- run ------------------------------------------------------------------
async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    await db.init()
    api = TelegramAPIServer.from_base(LOCAL_API, is_local=True) if LOCAL_API else None
    session = AiohttpSession(api=api, timeout=1800) if api else AiohttpSession(timeout=1800)
    bot = Bot(BOT_TOKEN, session=session, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher(storage=MemoryStorage())
    dp.message.outer_middleware(Gate())
    dp.callback_query.outer_middleware(Gate())
    dp.include_routers(adm, r)
    await bot.set_my_commands([BotCommand(command="menu", description="Главное меню")])
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
