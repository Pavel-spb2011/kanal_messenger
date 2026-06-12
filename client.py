from tkinter import messagebox, simpledialog
from typing import Optional, List, Dict, Callable
from threading import Thread, Lock
from socket import socket, AF_INET, SOCK_STREAM, timeout as socket_timeout
from datetime import datetime, date, timezone
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from json import load, dump, loads, dumps
from os import path, urandom
from pyperclip import paste, copy
from collections import defaultdict
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import customtkinter as ctk
import tkinter as tk
import struct
import secrets
import hashlib
import hmac
import traceback
import base64
import threading


# Константы
SERVER_PUBLIC_KEY_HEX = "8b251224d95cd367bf4c134cad0fe441a2df60a7ecfa3d91472f27de55a377b6"
SERVER_PUBLIC_KEY_BYTES = bytes.fromhex(SERVER_PUBLIC_KEY_HEX)
SERVER_PUBLIC_KEY = ed25519.Ed25519PublicKey.from_public_bytes(SERVER_PUBLIC_KEY_BYTES)

DH_P = int("""
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
""".replace(" ", "").replace("\n", ""), 16)
DH_G = 2

MAX_CT_LENGTH = 1_048_576

HOST = "127.0.0.1"
PORT = 45779



def encrypt_aes_gcm(key, plaintext, associated_data=b''):
    iv = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(associated_data)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext

def decrypt_aes_gcm(key, ciphertext, associated_data=b''):
    iv = ciphertext[:12]
    tag = ciphertext[12:28]
    actual_ciphertext = ciphertext[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(associated_data)
    return decryptor.update(actual_ciphertext) + decryptor.finalize()


def _derive_key(key: bytes) -> bytes:
    return hashlib.sha256(key).digest()

def _derive_db_key(password: str, salt: bytes) -> bytes:
    key = hashlib.sha256(password.encode('utf-8') + salt).digest()
    for _ in range(200_000 - 1):  # первая итерация уже сделана
        key = hashlib.sha256(key + salt).digest()
    return key


def encrypt_db(data: dict, password: str) -> str:
    if not isinstance(data, dict):
        raise TypeError("data must be a dict")
    if not password:
        raise ValueError("password must not be empty")

    # Генерируем новую соль при каждом сохранении (или один раз при создании)
    salt = urandom(32)
    key = _derive_db_key(password, salt)
    
    plaintext = dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    aesgcm = AESGCM(key)
    nonce = urandom(12)
    encrypted = aesgcm.encrypt(nonce, plaintext, None)

    payload = {
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(encrypted).decode("ascii"),
    }
    return dumps(payload, ensure_ascii=False)

def decrypt_db(token: str, password: str) -> dict:
    if not isinstance(token, str):
        raise TypeError("token must be a string")
    if not password:
        raise ValueError("password must not be empty")

    payload = loads(token)
    
    # Проверяем наличие соли
    if "salt" in payload:
        salt = base64.b64decode(payload["salt"])
        key = _derive_db_key(password, salt)
    else:
        # Старый формат без соли – для совместимости
        key = hashlib.sha256(password.encode("utf-8")).digest()

    nonce = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return loads(plaintext.decode("utf-8"))


def encrypt(text: str, key: str) -> str:
    aes_key = _derive_key(key)
    aesgcm = AESGCM(aes_key)
    nonce = urandom(12)
    ciphertext = aesgcm.encrypt(nonce, text.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("utf-8")

def decrypt(text: str, from_: str) -> str:
    raw = base64.b64decode(text.encode("utf-8"))
    nonce = raw[:12]
    ciphertext = raw[12:]
    key = app.db.get_symmetric_key(from_)
    aes_key = _derive_key(key)
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


def gen_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Экспорт в PEM и печать в консоль в виде копируемой строки
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public = f"\"\"\"{public_pem.decode()}\"\"\""

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    private = f"\"\"\"{private_pem.decode()}\"\"\""

    return public, private



# База данных
class DB:
    def __init__(self, auto_continue=False, password=""):
        self.privkey = ""
        if auto_continue:
            self.continue_init(password)

    def continue_init(self, password, reg=False):
        self.password = password
        self.username = app.username
        self.db_path = f"data_{self.username}.json"
        self.keys = {}

        if path.exists(self.db_path):
            try:
                with open(self.db_path, 'r', encoding='utf-8') as f:
                    self.data = load(f)
                    
            except Exception:
                self.data = {"privkey": "", "sci": {}, "chats": {}, "keys": {}}
                self._save_to_file()
            self.data = decrypt_db(self.data, self.password)

        else:
            self.data = {"privkey": "", "sci": {}, "chats": {}, "keys": {}}
            self._save_to_file()

        if reg:
            self.save_privkey(app.sktp.keys[1])
            self.privkey = app.sktp.keys[1]
            app.sktp.send_pubkey()
        else:
            try:
                self.privkey = serialization.load_pem_private_key(self.data["privkey"].encode(), password=None)
            except:
                self.privkey = ""
                messagebox.showerror("Ошибка", "Приватного ключа нет в локальной базе данных")

        # Восстановление симметричных ключей из файла
        keys_raw = self.data.get("keys", {})
        for user, b64key in keys_raw.items():
            try:
                self.keys[user] = base64.b64decode(b64key)
            except Exception:
                pass

    def _save_to_file(self):
        with open(self.db_path, 'w', encoding='utf-8') as f:
            dump(encrypt_db(self.data, self.password), f, indent=2, ensure_ascii=False)


    def save_message_to_history(self, chat_name, sender, text, timestamp=None):
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).isoformat()
        msg = {
            "sender": sender,
            "text": text,
            "timestamp": timestamp
        }

        if "chats" not in self.data:
            self.data["chats"] = {}
        if chat_name not in self.data["chats"]:
            self.data["chats"][chat_name] = {
                "users": [],
                "messages": []
            }
        self.data["chats"][chat_name]["messages"].append(msg)
        self._save_to_file()

    def get_messages(self, chat_name):
        chat = self.data.get("chats", {}).get(chat_name)
        return chat.get("messages", []) if chat else []


    def save_chat_key(self, chat_name, key_bytes):
        if "chats" not in self.data:
            self.data["chats"] = {}
        if chat_name not in self.data["chats"]:
            self.data["chats"][chat_name] = {"users": [], "chat_key": "", "messages": []}
        self.data["chats"][chat_name]["chat_key"] = base64.b64encode(key_bytes).decode('ascii')
        self._save_to_file()

    def get_chat_key(self, chat_name):
        chat = self.data.get("chats", {}).get(chat_name)
        if chat and chat.get("chat_key"):
            return base64.b64decode(chat["chat_key"])
        return None


    def save_sci(self, sci_dict):
        self.data["sci"] = sci_dict
        self._save_to_file()

    def load_sci(self):
        return self.data.get("sci", {})


    def save_symmetric_key(self, user, key_bytes):
        self.keys[user] = key_bytes
        if "keys" not in self.data:
            self.data["keys"] = {}
        self.data["keys"][user] = base64.b64encode(key_bytes).decode('ascii')
        self._save_to_file()

    def get_symmetric_key(self, user):
        return self.keys.get(user)


    def save_privkey(self, privkey_pem):
        self.data["privkey"] = privkey_pem
        self._save_to_file()

    def load_privkey(self):
        return self.data.get("privkey", "")


# Сетевой протокол
class SKTP:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sci = {}
        self.send_lock = threading.Lock()
        self.pending_messages: Dict[str, List[dict]] = defaultdict(list)

    def connect(self, name, password, mode="auth"):
        try:
            self.client = socket(AF_INET, SOCK_STREAM)
            self.client.connect((self.host, self.port))
            self._get_keys(self._signature_check())
            if mode == "auth":
                return self._auth(name, password)
            else:
                self.keys = gen_keys()
                return self._reg(name, password)
                
        except Exception as e:
            messagebox.showerror("Ошибка", f"❌ Ошибка подключения: {e}")
            return False


    def send_packet(self, plaintext: bytes, associated_data=b'msg'):
        """Потокобезопасная отправка пакета (без ожидания)."""
        with self.send_lock:
            ciphertext = encrypt_aes_gcm(self.session_encryption_key, plaintext, associated_data)
            mac = hmac.new(self.session_hmac_key, ciphertext, hashlib.sha256).digest()
            self._send_raw(struct.pack('!H', len(mac)) + mac)
            self._send_raw(struct.pack('!I', len(ciphertext)))
            self._send_raw(ciphertext)

    def recv_packet(self, associated_data=b'msg') -> bytes:
        mac_len = struct.unpack('!H', self._recv_exact(2))[0]
        if mac_len != 32:
            messagebox.showerror(f"Некорректная длина HMAC: {mac_len}")
            return
        received_mac = self._recv_exact(mac_len)
        ct_len = struct.unpack('!I', self._recv_exact(4))[0]
        if ct_len > MAX_CT_LENGTH:
            messagebox.showerror(f"Длина шифротекста превышает допустимую: {ct_len}")
            return
        ciphertext = self._recv_exact(ct_len)
        expected_mac = hmac.new(self.session_hmac_key, ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(expected_mac, received_mac):
            error_msg = dumps({"type": "error", "reason": "hmac_mismatch"}).encode()
            try:
                self.send_packet(error_msg)
            except:
                pass
            return
        return decrypt_aes_gcm(self.session_encryption_key, ciphertext, associated_data)


    def send_msg(self, msgdata):
        """
        Если ключ для target уже согласован - отправляем сообщение.
        Иначе кладём в очередь и инициируем обмен ключами.
        """
        target = msgdata.get('target')
        if not target:
            return
        if self.sci.get(target, False):
            # sci = True – отправляем сразу
            msgdata["content"] = encrypt(msgdata["content"], key=app.db.get_symmetric_key(msgdata["target"]))
            self.send_packet(dumps(msgdata).encode('utf-8'))
        else:
            # Ключ ещё не готов: добавляем в очередь ожидания
            self.pending_messages[target].append(msgdata)

            # Запрос публичного ключа собеседника у сервера
            self.send_packet(dumps({"type": "get_pubkey", "target": target}).encode('utf-8')) # ожидаем {"type": "pubkey", "user": ..., "pubkey": ...}
            

    def _send_pending(self, target):
        """Отправляет все накопленные сообщения для target (после согласования ключа)."""
        msgs = self.pending_messages.pop(target, [])
        for m in msgs:
            m["content"] = encrypt(m["content"], key=app.db.get_symmetric_key(m["target"]))
            self.send_packet(dumps(m).encode('utf-8'))

    def _auth(self, name, password):
        auth_data = dumps({
            "type": "auth",
            "username": name,
            "password": password,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }).encode('utf-8')
        self.send_packet(auth_data)
        response_plain = self.recv_packet()
        auth_response = loads(response_plain.decode('utf-8'))
        if auth_response.get("status") != "authenticated":
            reason = auth_response.get("reason", "неизвестная ошибка")
            if reason == "username_taken":
                msg = "❌ Имя пользователя уже занято!"
            else:
                msg = f"❌ Не удалось войти: {reason}"
            messagebox.showerror("Ошибка", msg)
            return False

        self.stream = Thread(target=app.handle_server_messages)
        self.stream.start()
        return True
    
    def _reg(self, username: str, password: str) -> bool:
        self.send_packet(dumps({
                    "type": "reg",
                    "password": password,
                    "username": username,
                }).encode('utf-8'))
        ans = loads(self.recv_packet().decode('utf-8'))
        print(ans)
        if ans.get("type", "") == "report:success" and ans.get("status", "") == "authenticated":
            self.stream = Thread(target=app.handle_server_messages)
            self.stream.start()
            return True
        else:
            return False


    def send_pubkey(self):
        self.send_packet(dumps({"type": "pubkey", "pubkey": self.keys[0]}).encode("utf-8"))

    def _get_keys(self, dh_pub_bytes):
        server_public = int(dh_pub_bytes.decode('utf-8'))
        private = secrets.randbelow(DH_P - 1) + 1
        public = pow(DH_G, private, DH_P)
        client_dh_bytes = str(public).encode('utf-8')
        self._send_raw(struct.pack('!I', len(client_dh_bytes)))
        self._send_raw(client_dh_bytes)
        shared = pow(server_public, private, DH_P)
        encryption_key, hmac_key = self._derive_keys(shared)
        self.session_encryption_key = encryption_key
        self.session_hmac_key = hmac_key

    def _signature_check(self):
        server_pub = self._recv_exact(32)
        if server_pub != SERVER_PUBLIC_KEY_BYTES:
            raise ValueError("Публичный ключ сервера не совпадает!")
        signature = self._recv_exact(64)
        dh_pub_len = struct.unpack('!I', self._recv_exact(4))[0]
        if dh_pub_len > 4096:
            raise ValueError("Некорректная длина DH-ключа сервера")
        dh_pub_bytes = self._recv_exact(dh_pub_len)
        try:
            SERVER_PUBLIC_KEY.verify(signature, dh_pub_bytes)
        except InvalidSignature:
            raise ValueError("Подпись сервера недействительна!")
        return dh_pub_bytes

    def _derive_keys(self, shared_secret):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 32 + 32 байта
            salt=None,
            info=b"session_keys",
        )
        key_material = hkdf.derive(str(shared_secret).encode())
        encryption_key = key_material[:32]
        hmac_key = key_material[32:]
        return encryption_key, hmac_key

    def _send_raw(self, data: bytes):
        self.client.sendall(data)

    def _recv_exact(self, n: int) -> bytes:
        data = b''
        while len(data) < n:
            chunk = self.client.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Соединение закрыто")
            data += chunk
        return data


# UI
class Avatar(ctk.CTkFrame):
    def __init__(self, master, text: str, size: int = 30, fg_color: str = "#2E7D32", **kwargs):
        super().__init__(master, width=size, height=size, fg_color=fg_color, corner_radius=size // 2, **kwargs)
        self.pack_propagate(False)
        self.grid_propagate(False)
        label = ctk.CTkLabel(self, text=text[:2].upper(),
                             font=ctk.CTkFont(size=size // 2, weight="bold"),
                             text_color="white")
        label.place(relx=0.5, rely=0.5, anchor="center")

class ChatBubbleFrame(ctk.CTkScrollableFrame):
    def __init__(self, master, my_name: str, profile_callback: Optional[callable] = None):
        super().__init__(master, fg_color="transparent")
        self.my_name = my_name
        self.profile_callback = profile_callback
        self.last_date_str = None
        self._user_scrolled = False

        self.scroll_down_btn = ctk.CTkButton(master, text="⬇", width=30, height=30,
                                             corner_radius=15, fg_color="#3A3A3A",
                                             command=self._scroll_to_bottom)
        self.scroll_down_btn.place(relx=0.95, rely=0.9, anchor="se")
        self.scroll_down_btn.lower()

        self._parent_canvas.bind("<Enter>", self._bind_scroll)
        self._parent_canvas.bind("<Leave>", self._unbind_scroll)

    def _bind_scroll(self, event):
        self._parent_canvas.bind("<MouseWheel>", self._on_user_scroll)

    def _unbind_scroll(self, event):
        self._parent_canvas.unbind("<MouseWheel>")

    def _on_user_scroll(self, event):
        self._user_scrolled = True
        self._check_if_bottom()

    def _check_if_bottom(self):
        if self._parent_canvas.yview()[1] >= 0.98:
            self._user_scrolled = False
            self.scroll_down_btn.lower()
        else:
            self.scroll_down_btn.lift()

    def _scroll_to_bottom(self):
        self.update_idletasks()
        self._parent_canvas.yview_moveto(1.0)
        self._user_scrolled = False
        self.scroll_down_btn.lower()

    def _add_date_divider(self, date_str: str):
        divider = ctk.CTkFrame(self, fg_color="transparent", height=20)
        divider.pack(fill="x", pady=5)
        ctk.CTkLabel(divider, text=date_str, font=ctk.CTkFont(size=10),
                     text_color="gray").pack(side="left", padx=50)

    def add_message(self, sender: str, text: str, timestamp: Optional[datetime] = None):
        if timestamp is None:
            timestamp = datetime.now()
        time_str = timestamp.strftime("%H:%M")

        today = date.today()
        msg_date = timestamp.date()
        if msg_date == today:
            date_str = "Сегодня"
        elif msg_date == today.replace(day=today.day - 1):
            date_str = "Вчера"
        else:
            date_str = msg_date.strftime("%d.%m.%Y")

        if date_str != self.last_date_str:
            self._add_date_divider(date_str)
            self.last_date_str = date_str

        is_myself = (sender == self.my_name)
        bubble_fg = "#2E7D32" if is_myself else "#3A3A3A"
        text_color = "#FFFFFF" if is_myself else "#CDD6F4"
        anchor = "e" if is_myself else "w"

        bubble = ctk.CTkFrame(self, fg_color=bubble_fg, corner_radius=12)
        bubble.pack(pady=3, padx=10, anchor=anchor, fill="x", expand=False)

        name_label = None
        if not is_myself:
            name_label = ctk.CTkLabel(bubble, text=sender,
                                      font=ctk.CTkFont(size=11, weight="bold"),
                                      text_color="#A6E3A1")
            name_label.pack(anchor="w", padx=12, pady=(6, 0))
            if self.profile_callback:
                name_label.bind("<Button-1>", lambda e, s=sender: self.profile_callback(s))
                name_label.bind("<Button-3>", lambda e, s=sender: self._profile_menu(e, s))

        msg_label = ctk.CTkLabel(bubble, text=text,
                                 font=ctk.CTkFont(size=12),
                                 text_color=text_color,
                                 wraplength=380, justify="left")
        msg_label.pack(anchor="w", padx=12, pady=6)

        time_label = ctk.CTkLabel(bubble, text=time_str,
                                  font=ctk.CTkFont(size=9),
                                  text_color="gray")
        time_label.pack(anchor="e", padx=12, pady=(0, 6))

        for widget in (bubble, name_label, msg_label, time_label):
            if widget:
                widget.bind("<Button-3>", lambda e, t=text, s=sender: self._context_menu(e, t, s))

        self._auto_scroll()

    def _auto_scroll(self):
        self.update_idletasks()
        if not self._user_scrolled:
            self._parent_canvas.yview_moveto(1.0)
            self.scroll_down_btn.lower()
        else:
            self.scroll_down_btn.lift()

    def _context_menu(self, event, text: str, sender: Optional[str] = None):
        menu = tk.Menu(self, tearoff=0, bg='#2B2B2B', fg='#CDD6F4')
        menu.add_command(label="📋 Копировать текст", command=lambda: copy(text))
        if sender and self.profile_callback:
            menu.add_command(label="👤 Профиль", command=lambda: self.profile_callback(sender))
        menu.tk_popup(event.x_root, event.y_root)

    def _profile_menu(self, event, sender: str):
        menu = tk.Menu(self, tearoff=0, bg='#2B2B2B', fg='#CDD6F4')
        if self.profile_callback:
            menu.add_command(label="👤 Профиль", command=lambda: self.profile_callback(sender))
        menu.tk_popup(event.x_root, event.y_root)

    def clear(self):
        for child in self.winfo_children():
            child.destroy()
        self.last_date_str = None

class ProfileWindow(ctk.CTkToplevel):
    def __init__(self, master, data: dict):
        super().__init__(master)
        self.title("Профиль")
        self.geometry("300x250")
        self.resizable(False, False)
        self.attributes('-topmost', True)

        username = data.get("username", "Неизвестный")
        iw = data.get("iw", "")
        online = data.get("online", False)
        created_at = data.get("created_at", "")

        date_str = ""
        if created_at:
            try:
                dt = datetime.fromisoformat(created_at)
                date_str = dt.strftime("%d.%m.%Y %H:%M")
            except:
                date_str = created_at

        frame = ctk.CTkFrame(self, corner_radius=10)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        Avatar(frame, text=username, size=60).pack(pady=(10, 5))
        ctk.CTkLabel(frame, text=username, font=ctk.CTkFont(size=16, weight="bold")).pack()
        ctk.CTkLabel(frame, text=iw, font=ctk.CTkFont(size=12), text_color="gray").pack(pady=(0, 10))

        status_text = "🟢 Online" if online else "⚫ Offline"
        ctk.CTkLabel(frame, text=status_text, font=ctk.CTkFont(size=12)).pack(pady=2)

        if date_str:
            ctk.CTkLabel(frame, text=f"На сервере с {date_str}",
                         font=ctk.CTkFont(size=10), text_color="gray").pack(pady=5)

        ctk.CTkButton(frame, text="Закрыть", command=self.destroy, width=100).pack(pady=10)


# Окно входа
class LoginFrame(ctk.CTkFrame):
    def __init__(self, master, on_login_success: Callable[[str, str], None], **kwargs):
        super().__init__(master, **kwargs)
        self.on_login_success = on_login_success
        self.username_var = ctk.StringVar()
        self.password_var = ctk.StringVar()
        self._setup_ui()

    def _setup_ui(self):
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(expand=True)

        title = ctk.CTkLabel(container, text="Добро пожаловать в мессенджер Канал",
                             font=ctk.CTkFont(size=20, weight="bold"))
        title.pack(pady=20)

        ctk.CTkLabel(container, text="Имя пользователя:").pack(anchor="w", padx=20, pady=(10, 0))
        self.username_entry = ctk.CTkEntry(container, textvariable=self.username_var, width=280)
        self.username_entry.pack(padx=20, pady=5)
        self.username_entry.focus()

        ctk.CTkLabel(container, text="Пароль:").pack(anchor="w", padx=20, pady=(10, 0))
        self.password_entry = ctk.CTkEntry(container, textvariable=self.password_var, width=280, show="*")
        self.password_entry.pack(padx=20, pady=5)

        btn_frame = ctk.CTkFrame(container, fg_color="transparent")
        btn_frame.pack(pady=25)

        login_btn = ctk.CTkButton(btn_frame, text="Войти", width=120,
                                  command=self._login,
                                  fg_color="#2E7D32", hover_color="#1B5E20")
        login_btn.pack(side="left", padx=10)

        register_btn = ctk.CTkButton(btn_frame, text="Регистрация", width=120,
                                     command=self._register_user,
                                     fg_color="#3A3A3A", hover_color="#4A4A4A")
        register_btn.pack(side="left", padx=10)

        self.bind("<Return>", lambda e: self._login())
        self.username_entry.bind("<Return>", lambda e: self._login())
        self.password_entry.bind("<Return>", lambda e: self._login())

    def _login(self):
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        if not username or not password:
            messagebox.showwarning("Ошибка", "Заполните все поля.")
            return
        # Здесь должна быть проверка логина (пока заглушка)
        if self._authenticate(username, password):
            self.destroy()
            self.on_login_success(username, password)
        else:
            messagebox.showerror("Ошибка", "Неверное имя пользователя или пароль.")

    def _register_user(self):
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        if not username or not password:
            messagebox.showwarning("Ошибка", "Заполните все поля.")
            return
        if self._create_account(username, password):
            messagebox.showinfo("Успех", "Регистрация прошла успешно.")
            self.destroy()
            app._on_login_success(username, password, reg=True)
        else:
            messagebox.showerror("Ошибка", "Регистрация не удалась. Возможно, имя занято.")

    def _authenticate(self, username: str, password: str) -> bool:
        return app.sktp.connect(username, password, mode="auth")

    def _create_account(self, username: str, password: str) -> bool:
        return app.sktp.connect(username, password, mode="reg")


# UI
class MessengerUI(ctk.CTkFrame):
    def __init__(self, parent,
                 username: str,
                 db=None,
                 on_send_message: Optional[callable] = None,
                 on_add_user: Optional[callable] = None,
                 on_request_profile: Optional[callable] = None,
                 on_create_chat: Optional[callable] = None,
                 on_get_room_users: Optional[callable] = None,
                 **kwargs):
        super().__init__(parent, **kwargs)
        self.username = username
        self.on_send_message = on_send_message
        self.on_add_user = on_add_user
        self.on_request_profile = on_request_profile
        self.on_create_chat = on_create_chat
        self.on_get_room_users = on_get_room_users
        self.db = db

        self.loaded_chats = []
        self.chats = {}
        self.chat_buttons = {}
        self.active_chat_name = None
        self.last_msg = ""
        self.running = True
        self.connection_status = tk.StringVar(value="offline")
        self.users_loaded = set()   # множество чатов, для которых список участников уже запрошен

        self.setup_ui()
        self.entry.focus()
        self.animate_online()

    def setup_ui(self):
        main_frame = ctk.CTkFrame(self, corner_radius=10)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        top_bar = ctk.CTkFrame(main_frame, height=40, corner_radius=8)
        top_bar.pack(fill="x", pady=(0, 10))

        self.profile_btn = ctk.CTkButton(top_bar, text="👤", width=30, height=30,
                                         command=lambda: self.show_profile(self.username),
                                         fg_color="transparent", hover_color="#2B2B2B")
        self.profile_btn.pack(side="left", padx=5)

        self.name_label = ctk.CTkLabel(top_bar, text=f" {self.username}",
                                       font=ctk.CTkFont(size=14, weight="bold"))
        self.name_label.pack(side="left", padx=5)

        self.status_label = ctk.CTkLabel(top_bar, textvariable=self.connection_status,
                                         font=ctk.CTkFont(size=12))
        self.status_label.pack(side="right", padx=15)

        content_frame = ctk.CTkFrame(main_frame)
        content_frame.pack(fill="both", expand=True)

        self.sidebar = ctk.CTkFrame(content_frame, width=220, corner_radius=8)
        self.sidebar.pack(side="left", fill="y", padx=(0, 10))

        sidebar_header = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        sidebar_header.pack(fill="x", padx=10, pady=(10, 5))
        ctk.CTkLabel(sidebar_header, text="Чаты", font=ctk.CTkFont(size=14, weight="bold")).pack(side="left")

        self.new_chat_btn = ctk.CTkButton(sidebar_header, text="➕", width=30, height=30,
                                          command=self.add_chat_tab_ui,
                                          fg_color="#2E7D32", hover_color="#1B5E20",
                                          corner_radius=6)
        self.new_chat_btn.pack(side="right")

        self.chat_list_frame = ctk.CTkScrollableFrame(self.sidebar, fg_color="transparent")
        self.chat_list_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.chat_area = ctk.CTkFrame(content_frame, corner_radius=8)
        self.chat_area.pack(side="right", fill="both", expand=True)

        bottom_frame = ctk.CTkFrame(main_frame, height=100, corner_radius=10)
        bottom_frame.pack(fill="x", pady=(10, 0))

        self.entry = ctk.CTkTextbox(bottom_frame, height=70, font=ctk.CTkFont(size=12),
                                    wrap="word", border_width=1)
        self.entry.pack(side="left", fill="both", expand=True, padx=(10, 5), pady=10)

        btn_frame = ctk.CTkFrame(bottom_frame, fg_color="transparent")
        btn_frame.pack(side="right", padx=(5, 10), pady=10)

        self.send_btn = ctk.CTkButton(btn_frame, text="📨 Отправить", width=100,
                                      command=self._on_send_click, corner_radius=8,
                                      fg_color="#2E7D32", hover_color="#1B5E20")
        self.send_btn.pack(pady=2)

        self.copy_btn = ctk.CTkButton(btn_frame, text="📋 Копировать", width=100,
                                      command=self.copy_msg, corner_radius=8,
                                      fg_color="#3A3A3A", hover_color="#4A4A4A")
        self.copy_btn.pack(pady=2)

        self.entry.bind("<Control-v>", lambda e: self.paste_text())
        self.entry.bind("<Control-V>", lambda e: self.paste_text())
        self.entry.bind("<Control-Return>", lambda e: self._on_send_click())

        self.add_chat_tab("Основной")

    def _on_send_click(self):
        chat_name = self.current_chat_name()
        msg = self.entry.get("0.0", "end").strip()
        if msg:
            self.on_send_message(chat_name, msg)
            self.entry.delete("0.0", "end")
            self.last_msg = msg

    def load_chat_history(self, chat_name: str):
        """Загружает и отображает историю сообщений чата из БД."""
        if not hasattr(app, 'db') or not app.db:
            return
        messages = app.db.get_messages(chat_name)
        for msg in messages:
            sender = msg.get("sender", "")
            text = msg.get("text", "")
            timestamp_str = msg.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(timestamp_str)
            except Exception:
                ts = datetime.now()
            if chat_name in self.chats:
                self.chats[chat_name]["widget"].add_message(sender, text, ts)

    def show_chat_info(self, chat_name: str):
        """Показать окно с информацией о чате и хешами симметричных ключей участников."""
        if chat_name not in self.chats or not self.db:
            return

        users = sorted(self.chats[chat_name]["users"])
        # Получаем общий ключ чата (если есть)
        chat_key = self.db.get_chat_key(chat_name)
        chat_key_hash = hashlib.sha256(chat_key).hexdigest() if chat_key else "отсутствует"

        # Готовим строки по каждому участнику
        lines = [f"Чат: {chat_name}", ""]
        lines.append("Участники группы и хеши ключей:" if len(users) != 1 else "В этой группе состоите только Вы.")
        for user in users:
            if user != self.username:
                sym_key = self.db.get_symmetric_key(user)
                if sym_key:
                    key_hash = hashlib.sha256(sym_key).hexdigest()
                    lines.append(f"{user}: {key_hash}")
                else:
                    lines.append(f"{user}: нет ключа")

        info_text = "\n".join(lines)

        # Создаём окно с информацией
        win = ctk.CTkToplevel(self)
        win.title(f"Информация: {chat_name}")
        win.geometry("400x350")
        win.attributes('-topmost', True)

        frame = ctk.CTkFrame(win)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        textbox = ctk.CTkTextbox(frame, wrap="word", font=ctk.CTkFont(size=12))
        textbox.insert("0.0", info_text)
        textbox.configure(state="disabled")  # только чтение
        textbox.pack(fill="both", expand=True)

        close_btn = ctk.CTkButton(frame, text="Закрыть", command=win.destroy)
        close_btn.pack(pady=(5, 0))

    def add_chat_tab(self, chat_name: str):
        if chat_name in self.chats:
            self.set_active_chat(chat_name)
            return

        chat_frame = ctk.CTkFrame(self.chat_area, corner_radius=8)

        users_frame = ctk.CTkFrame(chat_frame, corner_radius=8)
        users_frame.pack(fill="x", padx=10, pady=(10, 5))
        Avatar(users_frame, text=chat_name[0].upper(), size=28).pack(side="left", padx=5)
        users_label = ctk.CTkLabel(users_frame, text="👥 " + self.username,
                                   font=ctk.CTkFont(size=11))
        users_label.pack(side="left", padx=5)
        add_user_btn = ctk.CTkButton(users_frame, text="➕ Добавить", width=90,
                                     command=lambda cn=chat_name: self.add_user_to_chat(cn),
                                     corner_radius=6, fg_color="#2B2B2B", hover_color="#3A3A3A")
        add_user_btn.pack(side="right", padx=5)
        
        info_btn = ctk.CTkButton(users_frame, text="ℹ️", width=30, height=30,
                         command=lambda cn=chat_name: self.show_chat_info(cn),
                         corner_radius=6, fg_color="#2B2B2B", hover_color="#3A3A3A")
        info_btn.pack(side="right", padx=5)

        bubble_frame = ChatBubbleFrame(chat_frame, self.username, profile_callback=self.show_profile)
        bubble_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.chats[chat_name] = {
            "frame": chat_frame,
            "widget": bubble_frame,
            "users": {self.username},
            "users_label": users_label,
            "unread": 0,
            "button": None,
            "unread_label": None,
            "del_btn": None,
        }

        if chat_name not in self.loaded_chats:
            self.load_chat_history(chat_name)
            self.loaded_chats.append(chat_name)

        btn_frame = ctk.CTkFrame(self.chat_list_frame, fg_color="transparent")
        btn_frame.pack(fill="x", padx=5, pady=2)
        Avatar(btn_frame, text=chat_name[0].upper(), size=24).pack(side="left", padx=5)

        btn = ctk.CTkButton(btn_frame, text=f" {chat_name}", anchor="w",
                            command=lambda cn=chat_name: self.set_active_chat(cn),
                            fg_color="transparent", hover_color="#2B2B2B", corner_radius=6)
        btn.pack(side="left", fill="x", expand=True)

        unread_label = ctk.CTkLabel(btn_frame, text="", font=ctk.CTkFont(size=9),
                                    text_color="white", fg_color="#E06C75", corner_radius=10,
                                    width=20, height=20)
        unread_label.pack(side="right", padx=5)
        unread_label.pack_forget()

        self.chats[chat_name]["button"] = btn
        self.chats[chat_name]["unread_label"] = unread_label
        self.chat_buttons[chat_name] = btn

        if self.active_chat_name is None:
            self.set_active_chat(chat_name)

    def add_chat_tab_ui(self):
        name = simpledialog.askstring("Создать чат", "Введите имя чата:")
        if name and name not in self.chats:
            if self.on_create_chat:
                self.on_create_chat(name)
            else:
                self.add_chat_tab(name)
            self.set_active_chat(name)

    def set_active_chat(self, chat_name: str):
        if self.active_chat_name == chat_name:
            return
        if self.active_chat_name and self.active_chat_name in self.chats:
            self.chats[self.active_chat_name]["frame"].pack_forget()
        if chat_name in self.chats:
            data = self.chats[chat_name]
            data["frame"].pack(fill="both", expand=True, padx=5, pady=5)
            self.active_chat_name = chat_name

            # Запрос списка участников только при первом открытии чата за сессию
            if self.on_get_room_users and chat_name not in self.users_loaded:
                self.on_get_room_users(chat_name)
                self.users_loaded.add(chat_name)

            if chat_name not in self.loaded_chats:
                self.load_chat_history(chat_name)
                self.loaded_chats.append(chat_name)
            data["unread"] = 0
            self._update_chat_button(chat_name)
            for name, btn in self.chat_buttons.items():
                btn.configure(fg_color="#2E7D32" if name == chat_name else "transparent")

            if hasattr(app, 'active_chat_name'):
                app.active_chat_name = chat_name

    def current_chat_name(self) -> str:
        return self.active_chat_name or "Основной"

    def add_message_to_chat(self, chat_name: str, sender: str, text: str):
        if chat_name in self.chats:
            self.chats[chat_name]["widget"].add_message(sender, text)

    def clear_chat(self, chat_name: str):
        if chat_name in self.chats:
            self.chats[chat_name]["widget"].clear()

    def set_users(self, chat_name: str, users_list: List[str]):
        if chat_name not in self.chats:
            self.add_chat_tab(chat_name)
        if self.username not in users_list:
            users_list.append(self.username)
        self.chats[chat_name]["users"] = set(users_list)
        self._update_users_label(chat_name)

    def add_user_local(self, chat_name: str, user: str):
        if chat_name not in self.chats:
            self.add_chat_tab(chat_name)
        if user != self.username:
            new_users = self.chats[chat_name]["users"] | {user}
            self.set_users(chat_name, list(new_users))

    def _update_users_label(self, chat_name: str):
        if chat_name in self.chats:
            users_list = list(self.chats[chat_name]["users"])
            text = "👥 " + ", ".join(users_list[:5]) + ("..." if len(users_list) > 5 else "")
            self.chats[chat_name]["users_label"].configure(text=text)

    def add_user_to_chat(self, chat_name: str):
        tgt = simpledialog.askstring("Добавить пользователя", f"Введите имя пользователя для добавления в чат '{chat_name}':")
        if tgt and self.on_add_user:
            self.on_add_user(chat_name, tgt)

    def show_profile(self, target_username: str):
        if self.on_request_profile:
            self.on_request_profile(target_username)
        else:
            messagebox.showinfo("Профиль", f"Нет данных для {target_username}")

    def display_profile_window(self, data: dict):
        ProfileWindow(self, data)

    def copy_msg(self):
        if self.last_msg:
            copy(self.last_msg)

    def paste_text(self):
        try:
            self.entry.insert("end", paste())
        except:
            pass

    def clear_entry(self):
        self.entry.delete("0.0", "end")

    def update_connection_status(self, text: str):
        self.connection_status.set(text)

    def show_notification(self, message: str):
        notif = ctk.CTkToplevel(self)
        notif.title("Уведомление")
        notif.geometry("300x120")
        notif.attributes('-topmost', True)
        ctk.CTkLabel(notif, text=message, wraplength=280).pack(pady=20)
        ctk.CTkButton(notif, text="OK", command=notif.destroy).pack()
        notif.after(5000, notif.destroy)

    def _update_chat_button(self, chat_name: str):
        data = self.chats.get(chat_name)
        if not data:
            return
        unread = data["unread"]
        label = data.get("unread_label")
        if unread > 0:
            label.configure(text=str(unread))
            label.pack(side="right", padx=5)
            data["button"].configure(fg_color="#E06C75")
        else:
            label.pack_forget()
            if self.active_chat_name != chat_name:
                data["button"].configure(fg_color="transparent")
            else:
                data["button"].configure(fg_color="#2E7D32")

    def animate_online(self):
        if not self.running:
            return
        current = self.connection_status.get()
        if "online" in current:
            if current.endswith("•"):
                self.connection_status.set(" online  ")
            else:
                self.connection_status.set(" online •")
        self.after(500, self.animate_online)


# Собственно мессенджер
class KanalMSG(ctk.CTk):
    def __init__(self):
        global db
        super().__init__()
        self.username = None
        self.password = None
        self.active_chat_name = "Основной"
        self.chats = {}
        self.sktp = None
        self.running = False
        self.db = None # class DB
        self.ui = None  # class MessengerUI

        # Инициализируем БД
        self.db = DB()
        db = self.db

        self.sktp = SKTP(HOST, PORT)

        self.title("Мессенджер Канал")
        self.after(100, lambda: self.state('zoomed'))

        # Показываем окно входа
        self.login_frame = LoginFrame(self, on_login_success=self._on_login_success)
        self.login_frame.pack(fill="both", expand=True)
 

    def _on_login_success(self, username: str, password: str, reg: bool=False):
        """Вызывается после успешного входа или регистрации."""
        self.username = username
        self.password = password

        self.db.continue_init(reg=reg, password=self.password)
        if reg:
            self.db = None
            self.db = DB(auto_continue=True, password=self.password) # Перезапускаем БД

        # Восстановление SCI и ключей
        saved_sci = self.db.load_sci()
        self.sktp.sci = {user: True for user, flag in saved_sci.items() if flag}
        for user in self.db.keys:
            if user not in self.sktp.sci:
                self.sktp.sci[user] = True
                self.db.save_sci(self.sktp.sci)

        # Убираем фрейм входа
        if self.login_frame:
            self.login_frame.destroy()
            self.login_frame = None

        # Создаём интерфейс мессенджера
        self.ui = MessengerUI(
            self,
            username=self.username,
            db=self.db,
            on_send_message=self.send,
            on_add_user=self.add_user_to_chat,
            on_request_profile=self.request_profile,
            on_create_chat=self.create_chat,
            on_get_room_users=self.request_room_users   # новый колбэк
        )
        self.ui.pack(fill="both", expand=True)

        # Восстановление чатов из БД (только история, без списков участников)
        if self.db:
            for chat_name in self.db.data.get("chats", {}).keys():
                if chat_name not in self.ui.chats:
                    self.ui.add_chat_tab(chat_name)  # внутри add_chat_tab уже вызовется load_chat_history
                else:
                    if chat_name not in self.ui.loaded_chats:
                        self.ui.load_chat_history(chat_name)
                        self.ui.loaded_chats.append(chat_name)
                # список участников не загружаем – он будет запрошен с сервера при первом открытии

        # Подключаемся к серверу
        if not self.sktp.client:
            if not self.sktp.connect(self.username, self.password):
                messagebox.showerror("Ошибка", "Не удалось подключиться к серверу.")
                self.destroy()
                return

        self.ui.update_connection_status("online")
        self.running = True

    def _ask_join_room(self, chat_name, inviter):
        accept = messagebox.askyesno(
            "Приглашение в чат",
            f"Пользователь «{inviter}» приглашает вас в чат «{chat_name}». Принять?"
        )
        response = {
            "type": "answer:chat_join",
            "chat": chat_name,
            "result": accept
        }
        try:
            self.sktp.send_packet(dumps(response).encode('utf-8'))
        except Exception as e:
            print(f"Ошибка отправки ответа на приглашение: {e}")

        if accept:
            self.ui.add_chat_tab(chat_name)

    def request_room_users(self, chat_name: str):
        """Запрашивает с сервера актуальный список участников комнаты."""
        if not self.running:
            return
        packet = dumps({
            "type": "get_room_users",
            "chat": chat_name
        }).encode('utf-8')
        try:
            self.sktp.send_packet(packet)
        except Exception as e:
            print(f"Ошибка запроса списка участников комнаты {chat_name}: {e}")

    def handle_server_messages(self):
        global decrypted_key
        self.running = True
        while self.running:
            try:
                text = self.sktp.recv_packet()
                message_data = loads(text.decode('utf-8'))

                match message_data.get("type"):
                    case "message":
                        chat_name = message_data.get("chat", "Основной")
                        sender = message_data.get("sender", "Неизвестный")
                        content = decrypt(message_data.get("content", ""), from_=sender) if message_data.get("content", "") else ""

                        if chat_name not in self.ui.chats:
                            self.after(0, self.ui.add_chat_tab, chat_name)
                            self.after(50, self.ui.add_message_to_chat, chat_name, sender, content)
                            self.after(50, self.db.save_message_to_history, chat_name, sender, content)
                        else:
                            self.after(0, self.ui.add_message_to_chat, chat_name, sender, content)
                            self.after(0, self.db.save_message_to_history, chat_name, sender, content)

                        if self.active_chat_name != chat_name:
                            data = self.ui.chats.get(chat_name)
                            if data:
                                data["unread"] += 1
                                self.after(0, self.ui._update_chat_button, chat_name)
                                self.after(0, self.ui.show_notification, f"Новое сообщение в чате \"{chat_name}\" от {sender}")

                    case "room.users_list":
                        chat_name = message_data.get("chat", "Основной")
                        users_list = message_data.get("users", [])
                        self.after(0, self._on_room_users_list, chat_name, users_list)

                    case "event:new_in_room":
                        chat_name = message_data.get("chat")
                        user = message_data.get("user")
                        self.after(0, self._on_user_joined, chat_name, user)

                    case "request:join_room":
                        chat_name = message_data.get("chat")
                        inviter = message_data.get("inviter")
                        if chat_name and inviter:
                            self.after(0, self._ask_join_room, chat_name, inviter)

                    case "key_answer":
                        sender = message_data.get("sender")
                        encrypted_key = base64.b64decode(message_data.get("content"))
                        decrypted_key = self.db.privkey.decrypt(encrypted_key, padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        ))
                        expected_key = db.get_symmetric_key(sender)
                        if expected_key and decrypted_key == expected_key:
                            answer = {
                                "type": "report:key_ok",
                                "content": "succes",
                                "sender": self.username,
                                "target": message_data.get("sender"),
                                "hmac": hmac.new(decrypted_key, b'ok', hashlib.sha256).hexdigest(),
                            }
                            self.sktp.send_packet(dumps(answer).encode('utf-8'))
                            self.sktp.sci[sender] = True
                            db.save_sci(self.sktp.sci)
                            self.sktp._send_pending(sender)

                    case "key":
                        sender = message_data.get("sender")
                        encrypted_key_b64 = message_data.get("content")
                        if not sender or not encrypted_key_b64:
                            break
                        try:
                            encrypted_key = base64.b64decode(encrypted_key_b64)
                            decrypted_key = self.db.privkey.decrypt(
                                encrypted_key,
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                )
                            )
                            self.db.save_symmetric_key(sender, decrypted_key)
                            self.sktp.sci[sender] = True
                            self.db.save_sci(self.sktp.sci)

                            # Запрос публичного ключа собеседника у сервера
                            self.sktp.send_packet(dumps({"type": "get_pubkey2", "target": sender}).encode('utf-8'))
                        except Exception:
                            pass
                    
                    case "pubkey2":
                        if message_data.get("pubkey"):
                            pubkey = serialization.load_pem_public_key(message_data["pubkey"].encode())
                            re_encrypted_key = pubkey.encrypt(
                                decrypted_key,
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                )
                            )
                            answer_packet = {
                                "type": "key_answer",
                                "sender": self.username,
                                "target": sender,
                                "content": base64.b64encode(re_encrypted_key).decode('ascii')
                            }
                            self.sktp.send_packet(dumps(answer_packet).encode('utf-8'))

                        else:messagebox.showerror("Ошибка", "Ошибка обмена ключами")

                    case "report:key_ok":
                        sender = message_data.get("sender")
                        expected_hmac = hmac.new(db.keys.get(sender, b''), b'ok', hashlib.sha256).hexdigest()
                        if message_data.get("hmac") == expected_hmac:
                            self.sktp.sci[sender] = True
                            db.save_sci(self.sktp.sci)
                            if sender in db.keys:
                                db.save_symmetric_key(sender, db.keys[sender])
                            self.sktp._send_pending(sender)

                    case "report:user_add":
                        if message_data.get("success", False):
                            self.after(0, messagebox.showinfo, "Успешно", f"Пользователь \"{message_data.get('user')}\" добавлен в чат \"{message_data.get('chat')}\"")
                        else:
                            self.after(0, messagebox.showerror, "Ошибка", message_data.get("message", "Не удалось добавить пользователя"))

                    case "report:error":
                        reason = message_data.get("reason", "неизвестная ошибка")
                        if reason == "user_not_found":
                            self.after(0, messagebox.showerror, "Ошибка", "Пользователь не найден")
                        else:
                            self.after(0, messagebox.showerror, "Ошибка", f"Сервер сообщил об ошибке: {reason}")

                    case "profile_info":
                        self.after(0, self.ui.display_profile_window, message_data)

                    case "connection_check":
                        answer = {
                                "type": "connection_check_answer",
                                "content": True,
                            }
                        self.sktp.send_packet(dumps(answer).encode('utf-8'))

                    case "pubkey":
                        # Обработка ответа сервера на запрос pubkey пользователя
                        if message_data.get("pubkey"):
                            pubkey = serialization.load_pem_public_key(message_data["pubkey"].encode())
                            
                            generated_key = secrets.token_bytes(32)
                            
                            ciphertext = pubkey.encrypt(
                                generated_key,
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                )
                            )
                            packet = {
                                "type": "key",
                                "sender": self.username,
                                "target": message_data["user"],
                                "content": base64.b64encode(ciphertext).decode('ascii'),
                            }
                            self.sktp.send_packet(dumps(packet).encode('utf-8'))
                            packet = None
                            
                            db.save_symmetric_key(message_data["user"], generated_key)
                        else:
                            messagebox.showerror("Ошибка", "Ошибка обмена ключами")


            except socket_timeout:
                continue
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, ConnectionError):
                break
            except Exception as e:
                print(f"Ошибка приёма: {e}")
                traceback.print_exc()
                break

        try:
            if hasattr(self, 'client') and self.sktp.client:
                self.sktp.client.close()
                self.sktp.client = None
        except:pass

    def _on_room_users_list(self, chat_name, users_list):
        try:self.ui.set_users(chat_name, users_list)
        except AttributeError:pass

    def _on_user_joined(self, chat_name, user):
        self.ui.add_user_local(chat_name, user)

    def send(self, chat_name, msg):
        if msg and self.running:
            self.ui.add_message_to_chat(chat_name, self.username, msg)
            if chat_name in self.ui.chats:
                users = list(self.ui.chats[chat_name]["users"] - {self.username})

            for user in users:
                message_data = {
                    "type": "message",
                    "chat": chat_name,
                    "content": msg,
                    "sender": self.username,
                    "target": user,
                }
                self.sktp.send_msg(message_data)
            self.ui.clear_entry()
            self.db.save_message_to_history(chat_name, self.username, msg)

    def join_room(self, chat_name):
        if not self.running:
            return
        packet = dumps({"type": "join_room", "chat": chat_name}).encode('utf-8')
        try:
            self.sktp.send_packet(packet)
        except Exception as e:
            print(f"Ошибка при входе в комнату {chat_name}: {e}")

    def add_user_to_chat(self, chat_name, target):
        if not self.running:
            return
        packet = dumps({
            "type": "add_user",
            "chat": chat_name,
            "target": target
        }).encode('utf-8')
        try:
            self.sktp.send_packet(packet)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось добавить пользователя: {e}")

    def request_profile(self, target_username):
        if not self.running:
            return
        packet = dumps({
            "type": "get_profile",
            "target_username": target_username
        }).encode('utf-8')
        try:
            self.sktp.send_packet(packet)
        except Exception as e:
            print(f"Ошибка запроса профиля: {e}")

    def create_chat(self, chat_name):
        if chat_name in self.ui.chats:
            return
        self.ui.add_chat_tab(chat_name)
        self.join_room(chat_name)


if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    app = KanalMSG()
    app.mainloop()

# © КаналMSG, 2026
