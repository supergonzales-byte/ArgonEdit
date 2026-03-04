#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import ctypes
import signal
import time
import struct
import tempfile
import subprocess
import platform
import re
import secrets
import random
from pathlib import Path
import tkinter as tk
import tkinter.filedialog as filedialog

import customtkinter as ctk
from CTkMessagebox import CTkMessagebox
from CTkToolTip import CTkToolTip

from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from argon2.low_level import hash_secret_raw, Type

# CONFIGURATION CTK
ctk.set_appearance_mode("dark")  # "dark", "light", "system"
ctk.set_default_color_theme("blue")  # "blue", "green", "dark-blue"

# Configuration de l'application
MEMORY_COST = 262_144
TIME_COST = 6
PARALLELISM = 2
KEY_LEN = 32
SALT_SIZE = 32
NONCE_SIZE = 12
MAGIC = b"ARGONCRYPT_V3_INC\x00"
TARGET_DIRECTORY = Path.home() / "Private"
MASTER_PASSWORD = None
MASTER_PASSWORD_ENABLED = False

# Couleurs personnalisées
COLORS = {
    "primary": "#2E86AB",
    "secondary": "#A23B72",
    "success": "#18A558",
    "danger": "#F03A47",
    "warning": "#F9C80E",
    "dark": "#1C1C1E",
    "darker": "#0A0A0A",
    "light": "#F5F5F7",
    "lighter": "#FFFFFF",
    "gray": "#8E8E93",
    "gray_dark": "#636366",
    "editor_bg": "#1E1E1E",
    "editor_fg": "#F0F0F0",
    "sidebar": "#2C2C2E",
    "card": "#2C2C2E",
    "hover": "#3A3A3C",
}

class SecureExceptionContext:
    
    @staticmethod
    def clean_traceback():
        exc_type, exc_value, exc_traceback = sys.exc_info()
        if exc_traceback:
            tb = exc_traceback
            while tb:
                # Effacer les variables locales du frame
                tb.tb_frame.clear()
                tb = tb.tb_next
    
    @staticmethod
    def generic_error_message(original_error=None):
        return "Opération échouée (vérifiez vos informations d'authentification)"

# Structures de données sécurisées
class SecureList:
    __slots__ = ['_items']  # Évite __dict__ pour limiter l'exposition
    
    def __init__(self, initial_items=None):
        self._items = []
        if initial_items:
            for item in initial_items:
                self.append(item)
    
    def append(self, item):
        self._items.append(item)
    
    def extend(self, items):
        for item in items:
            self.append(item)
    
    def clear(self):
        for i, item in enumerate(self._items):
            if hasattr(item, 'clear'):
                item.clear()
            elif isinstance(item, (bytes, bytearray)):
                self._items[i] = b'\x00' * len(item)
            elif isinstance(item, str):
                self._items[i] = '\x00' * len(item)
        self._items.clear()
    
    def __len__(self):
        return len(self._items)
    
    def __getitem__(self, index):
        return self._items[index]
    
    def __setitem__(self, index, value):
        # Nettoyer l'ancienne valeur
        old = self._items[index]
        if hasattr(old, 'clear'):
            old.clear()
        self._items[index] = value
    
    def __delitem__(self, index):
        # Nettoyer avant suppression
        item = self._items[index]
        if hasattr(item, 'clear'):
            item.clear()
        elif isinstance(item, (bytes, bytearray)):
            self._items[index] = b'\x00' * len(item)
        del self._items[index]
    
    def __del__(self):
        self.clear()

# Allocation système sécurisée
class SystemAllocatedBuffer:
    
    def __init__(self, size):
        self._size = size
        self._ptr = ctypes.create_string_buffer(size)
        
        if os.name == 'nt':
            try:
                ctypes.windll.kernel32.VirtualLock(self._ptr, size)
            except:
                pass
    
    def write(self, data):
        if len(data) > self._size:
            raise ValueError(f"Data too large: {len(data)} > {self._size}")
        ctypes.memmove(self._ptr, data, len(data))
    
    def read(self, length=None):
        if length is None:
            length = self._size
        return bytes(self._ptr[:length])
    
    def clear(self):
        ctypes.memset(self._ptr, 0, self._size)
    
    def __del__(self):
        self.clear()
        if os.name == 'nt':
            try:
                ctypes.windll.kernel32.VirtualUnlock(self._ptr, self._size)
            except:
                pass

# Gestion simplifiée des fichiers temporaires 
class TempFileManager:
    
    @staticmethod
    def clean_filename(filename: str) -> str:
        if filename.endswith('.enc'):
            filename = filename[:-4]
        
        # Remplacer les caractères problématiques
        invalid_chars = r'[<>:"/\\|?*\n\r\t]'
        clean_name = re.sub(invalid_chars, '_', filename)
        
        # Supprimer les espaces en début/fin
        clean_name = clean_name.strip()
        
        if not clean_name:
            clean_name = "fichier_temporaire"
        
        return clean_name
    
    @staticmethod
    def create_secure_temp_file(content: bytes = None) -> Path:
        temp_dir = Path(tempfile.gettempdir())
        
        random_name = f"argon_tmp_{secrets.token_hex(8)}_{int(time.time())}"
        temp_path = temp_dir / random_name
        
        try:
            if content:
                # Écrire contenu
                with open(temp_path, 'wb') as f:
                    f.write(content)
                
                # Permissions restrictives
                os.chmod(temp_path, 0o600)  # Lecture/écriture uniquement par l'utilisateur
                
                # Randomiser les timestamps
                random_time = random.randint(0, 2**31 - 1)
                os.utime(temp_path, (random_time, random_time))
            
            return temp_path
        except Exception:
            if content:
                fd, path = tempfile.mkstemp()
                os.close(fd)
                with open(path, 'wb') as f:
                    f.write(content)
                return Path(path)
            else:
                return Path(tempfile.mktemp())
    
    @staticmethod
    def open_with_default_app(file_path: Path) -> bool:
        try:
            if not file_path.exists():
                return False
            
            if file_path.stat().st_size == 0:
                return False
            
            try:
                current_time = time.time()
                os.utime(file_path, (current_time, current_time))
            except:
                pass
            
            if platform.system() == 'Darwin':
                subprocess.call(['open', str(file_path)])
            elif platform.system() == 'Windows':
                os.startfile(str(file_path))
            else:
                subprocess.call(['xdg-open', str(file_path)])
            
            return True
        except Exception:
            return False
    
    @staticmethod
    def secure_delete(temp_path: Path) -> bool:
        try:
            if not temp_path.exists():
                return True
            
            file_size = temp_path.stat().st_size
            for _ in range(3):
                try:
                    with open(temp_path, 'r+b') as f:
                        f.write(os.urandom(file_size))
                        f.flush()
                        os.fsync(f.fileno())
                except:
                    break
            
            random_time = random.randint(0, 2**31 - 1)
            try:
                os.utime(temp_path, (random_time, random_time))
            except:
                pass
            
            # Supprimer
            temp_path.unlink()
            return True
        except Exception:
            try:
                temp_path.unlink()
                return True
            except:
                return False

# Protection mémoire
if os.name == 'nt':
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    kernel32.VirtualLock.restype = ctypes.c_bool
    kernel32.VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    kernel32.VirtualUnlock.restype = ctypes.c_bool

def secure_zero_bytearray(ba: bytearray):
    if ba:
        for i in range(len(ba)):
            ba[i] = 0

def secure_zero_string(s: str) -> str:
    if s:
        return '\x00' * len(s)
    return s

def secure_zero_bytes(b: bytes) -> bytes:
    if b:
        return b'\x00' * len(b)
    return b''

class SecureBuffer:
    def __init__(self, data: bytes = None):
        self._size = len(data) if data else 0
        self._buffer = bytearray(data) if data else bytearray()
        
        if os.name == 'nt' and self._buffer:
            try:
                address = ctypes.addressof(ctypes.c_char.from_buffer(self._buffer))
                kernel32.VirtualLock(address, len(self._buffer))
            except:
                pass
        
    def get(self) -> bytearray:
        return self._buffer
    
    def execute_with_bytes(self, callback):
        temp_bytes = bytes(self._buffer)
        try:
            result = callback(temp_bytes)
            return result
        finally:
            # Nettoyer la copie temporaire
            temp_bytes = secure_zero_bytes(temp_bytes)
            del temp_bytes
    
    def clear(self):
        if self._buffer:
            secure_zero_bytearray(self._buffer)
            
            if os.name == 'nt':
                try:
                    address = ctypes.addressof(ctypes.c_char.from_buffer(self._buffer))
                    kernel32.VirtualUnlock(address, len(self._buffer))
                except:
                    pass
            
            self._buffer = bytearray()
            self._size = 0
    
    def __del__(self):
        self.clear()
    
    def __len__(self):
        return len(self._buffer)

# Fonctions crypto (AMÉLIORÉES)
def pack_crypto_params(memory_cost: int, time_cost: int, parallelism: int) -> bytes:
    data = struct.pack(">BIBBxxx", 0x03, memory_cost, time_cost, parallelism)
    return data

def unpack_crypto_params(header_data: bytes) -> dict:
    version, memory_cost, time_cost, parallelism = struct.unpack(">BIBBxxx", header_data)
    return {
        "MEMORY_COST": memory_cost,
        "TIME_COST": time_cost,
        "PARALLELISM": parallelism,
        "version": version
    }

class _DecryptOperation:
    
    def __init__(self, nonce: bytes, aad: bytes):
        self.nonce = nonce
        self.aad = aad
    
    def __call__(self, cipher_bytes: bytes, aes) -> bytes:
        return aes.decrypt(self.nonce, cipher_bytes, self.aad)

class _EncryptOperation:
    
    def __init__(self, nonce: bytes, aad: bytes):
        self.nonce = nonce
        self.aad = aad
    
    def __call__(self, plain_bytes: bytes, aes) -> bytes:
        return aes.encrypt(self.nonce, plain_bytes, self.aad)

def derive_key(password: SecureBuffer, salt: SecureBuffer, params: dict) -> SecureBuffer:
    key_raw = hash_secret_raw(
        secret=bytes(password.get()),
        salt=bytes(salt.get()),
        time_cost=params["TIME_COST"],
        memory_cost=params["MEMORY_COST"],
        parallelism=params["PARALLELISM"],
        hash_len=KEY_LEN,
        type=Type.ID
    )
    return SecureBuffer(key_raw)

def encrypt_secure(plaintext: SecureBuffer, key: SecureBuffer, nonce: bytes, aad: bytes) -> SecureBuffer:
    encrypt_op = _EncryptOperation(nonce, aad)
    
    def encrypt_callback(key_bytes):
        aes = AESGCMSIV(key_bytes)
        return plaintext.execute_with_bytes(
            lambda plain_bytes: encrypt_op(plain_bytes, aes)
        )
    
    ciphertext_raw = key.execute_with_bytes(encrypt_callback)
    
    encrypt_op.nonce = b'\x00' * len(encrypt_op.nonce)
    encrypt_op.aad = b'\x00' * len(encrypt_op.aad)
    del encrypt_op
    
    return SecureBuffer(ciphertext_raw)

def decrypt_secure(ciphertext: SecureBuffer, key: SecureBuffer, nonce: bytes, aad: bytes) -> SecureBuffer:
    decrypt_op = _DecryptOperation(nonce, aad)
    
    def decrypt_callback(key_bytes):
        aes = AESGCMSIV(key_bytes)
        return ciphertext.execute_with_bytes(
            lambda cipher_bytes: decrypt_op(cipher_bytes, aes)
        )
    
    plaintext_raw = key.execute_with_bytes(decrypt_callback)
    
    decrypt_op.nonce = b'\x00' * len(decrypt_op.nonce)
    decrypt_op.aad = b'\x00' * len(decrypt_op.aad)
    del decrypt_op
    
    return SecureBuffer(plaintext_raw)

def read_encrypted_file(encrypted_path: Path) -> dict:
    data = encrypted_path.read_bytes()
    
    if len(data) < 18 or data[:18] != MAGIC:
        raise ValueError("Format non supporté")
    offset = 18
    
    params_data = data[offset:offset + 10]
    offset += 10
    
    params = unpack_crypto_params(params_data)
    
    salt = SecureBuffer(data[offset:offset + SALT_SIZE])
    offset += SALT_SIZE
    
    nonce = data[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE
    
    ciphertext = SecureBuffer(data[offset:])
    
    associated_data = MAGIC + params_data
    
    return {
        "params": params,
        "salt": salt,
        "nonce": nonce,
        "ciphertext": ciphertext,
        "associated_data": associated_data
    }

def encrypt_file(source_file: Path, password: str, target_dir: Path, delete_original: bool = False) -> bool:
    try:
        # Lire le fichier
        with open(source_file, 'rb') as f:
            plaintext_data = f.read()
        
        # Nettoyer le mot de passe après utilisation
        password_buffer = SecureBuffer(password.encode('utf-8'))
        
        # Préparer les paramètres
        salt = os.urandom(SALT_SIZE)
        nonce = os.urandom(NONCE_SIZE)
        params = {
            "MEMORY_COST": MEMORY_COST,
            "TIME_COST": TIME_COST,
            "PARALLELISM": PARALLELISM
        }
        
        salt_buffer = SecureBuffer(salt)
        key = derive_key(password_buffer, salt_buffer, params)
        
        params_header = pack_crypto_params(MEMORY_COST, TIME_COST, PARALLELISM)
        associated_data = MAGIC + params_header
        
        plaintext = SecureBuffer(plaintext_data)
        ciphertext = encrypt_secure(plaintext, key, nonce, associated_data)
        
        output_name = source_file.name + '.enc'
        output_path = target_dir / output_name
        
        # Écrire le fichier chiffré
        with open(output_path, 'wb') as f:
            f.write(MAGIC)
            f.write(params_header)
            f.write(salt)
            f.write(nonce)
            f.write(bytes(ciphertext.get()))
        
        secure_list = SecureList([
            password_buffer, salt_buffer, key, plaintext, ciphertext
        ])
        secure_list.clear()
        
        password = secure_zero_string(password)
        plaintext_data = secure_zero_bytes(plaintext_data)
        salt = secure_zero_bytes(salt)
        nonce = secure_zero_bytes(nonce)
        
        if delete_original:
            try:
                source_file.unlink()
            except Exception as e:
                print(f"Attention: Impossible de supprimer le fichier original: {e}")
        
        return True
        
    except Exception as e:
        SecureExceptionContext.clean_traceback()
        error_msg = SecureExceptionContext.generic_error_message()
        print(f"Erreur lors du chiffrement: {error_msg}")
        return False

def decrypt_file_to_disk(encrypted_file: Path, password: str, output_path: Path) -> bool:
    try:
        file_info = read_encrypted_file(encrypted_file)
        
        password_buffer = SecureBuffer(password.encode('utf-8'))
        key = derive_key(password_buffer, file_info["salt"], file_info["params"])
        
        plaintext = decrypt_secure(
            file_info["ciphertext"],
            key,
            file_info["nonce"],
            file_info["associated_data"]
        )
        
        with open(output_path, 'wb') as f:
            f.write(bytes(plaintext.get()))
        
        secure_list = SecureList([
            password_buffer, key, plaintext,
            file_info["salt"], file_info["ciphertext"]
        ])
        secure_list.clear()
        
        # Écraser le mot de passe
        password = secure_zero_string(password)
        
        return True
        
    except Exception as e:
        SecureExceptionContext.clean_traceback()
        error_msg = SecureExceptionContext.generic_error_message()
        print(f"Erreur lors du déchiffrement: {error_msg}")
        return False

def verify_file_password(encrypted_path: Path, password: str) -> bool:
    try:
        file_info = read_encrypted_file(encrypted_path)
        
        password_buffer = SecureBuffer(password.encode('utf-8'))
        key = derive_key(password_buffer, file_info["salt"], file_info["params"])
        
        # Essayer de déchiffrer (sans sauvegarder)
        plaintext = decrypt_secure(
            file_info["ciphertext"],
            key,
            file_info["nonce"],
            file_info["associated_data"]
        )
        
        # Nettoyer la mémoire
        secure_list = SecureList([
            password_buffer, key, plaintext,
            file_info["salt"], file_info["ciphertext"]
        ])
        secure_list.clear()
        
        # Écraser le mot de passe
        password = secure_zero_string(password)
        
        return True
        
    except Exception:
        SecureExceptionContext.clean_traceback()
        return False

# Dialogues (AMÉLIORÉS pour nettoyer les widgets)
class PasswordDialog(ctk.CTkToplevel):
    def __init__(self, parent, title="Mot de passe", filename=""):
        super().__init__(parent)
        
        self.title(title)
        self.geometry("400x290")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        
        self.result = None
        self._destroyed = False
        
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (400 // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (290 // 2)
        self.geometry(f"400x290+{x}+{y}")
        
        self.configure(fg_color=COLORS["dark"])
        
        main_container = ctk.CTkFrame(self, fg_color=COLORS["dark"])
        main_container.pack(fill="both", expand=True, padx=20, pady=20)
        
        icon_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        icon_frame.pack(pady=(10, 15))
        
        ctk.CTkLabel(
            icon_frame,
            text="🔓",
            font=ctk.CTkFont(size=32),
            text_color=COLORS["primary"]
        ).pack()
        
        display_name = filename
        if filename.endswith('.enc'):
            display_name = filename[:-4]
        
        ctk.CTkLabel(
            main_container,
            text=display_name,
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["light"]
        ).pack(pady=(0, 5))
        
        ctk.CTkLabel(
            main_container,
            text="Entrez le mot de passe de déchiffrement",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["gray"]
        ).pack(pady=(0, 15))
        
        self.password_entry = ctk.CTkEntry(
            main_container,
            placeholder_text="Mot de passe...",
            show="•",
            height=40,
            width=300,
            font=ctk.CTkFont(size=13),
            fg_color=COLORS["card"],
            border_color=COLORS["primary"],
            border_width=1
        )
        self.password_entry.pack(pady=(0, 20))
        
        button_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        button_frame.pack(fill="x", pady=(0, 10))
        
        self.ok_button = ctk.CTkButton(
            button_frame,
            text="Ouvrir",
            command=self.ok,
            fg_color=COLORS["primary"],
            hover_color="#257399",
            height=45,
            font=ctk.CTkFont(size=14, weight="bold"),
            width=200
        )
        self.ok_button.pack(anchor="center")
        
        self.password_entry.bind('<Return>', lambda e: self.ok())
        self.bind('<Escape>', lambda e: self.cancel())
        
        self.protocol("WM_DELETE_WINDOW", self.cancel)
        
        self.after(100, self.focus_password_entry)
    
    def focus_password_entry(self):
        self.password_entry.focus()
    
    def clean_password_fields(self):
        if hasattr(self, 'password_entry'):
            # Effacer le contenu du widget
            self.password_entry.delete(0, 'end')
            # Forcer la mise à jour de l'interface
            self.password_entry.update()
            # Envoyer des événements factices pour écraser les buffers UI
            for _ in range(len("password")):
                self.password_entry.event_generate('<Key>')
    
    def ok(self):
        self.ok_button.configure(state="disabled")
        
        password = self.password_entry.get()
        if password:
            self.result = SecureBuffer(password.encode('utf-8'))
        
        self.clean_password_fields()
        
        if not self._destroyed:
            self._destroyed = True
            self.destroy()
    
    def cancel(self):
        self.clean_password_fields()
        
        if not self._destroyed:
            self._destroyed = True
            self.result = None
            self.destroy()
    
    def show(self):
        self.wait_window()
        return self.result

class DecryptToFileDialog(ctk.CTkToplevel):
    def __init__(self, parent, filename=""):
        super().__init__(parent)
        
        self.title("Déchiffrer un fichier")
        self.geometry("500x420")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        
        self.result = None
        self.output_path = None
        self._destroyed = False
        self.original_filename = filename
        
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (500 // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (420 // 2)
        self.geometry(f"500x420+{x}+{y}")
        
        self.configure(fg_color=COLORS["dark"])
        
        main_container = ctk.CTkFrame(self, fg_color=COLORS["dark"])
        main_container.pack(fill="both", expand=True, padx=25, pady=25)
        
        icon_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        icon_frame.pack(pady=(10, 15))
        
        ctk.CTkLabel(
            icon_frame,
            text="🔓",
            font=ctk.CTkFont(size=32),
            text_color=COLORS["primary"]
        ).pack()
        
        display_filename = filename
        if filename.endswith('.enc'):
            display_filename = filename[:-4]
        if len(display_filename) > 40:
            display_filename = display_filename[:37] + "..."
        
        ctk.CTkLabel(
            main_container,
            text=f"Déchiffrement de : {display_filename}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["light"],
            wraplength=450,
            justify="center"
        ).pack(pady=(0, 5))
        
        ctk.CTkLabel(
            main_container,
            text="Entrez le mot de passe et choisissez l'emplacement de sortie",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["gray"]
        ).pack(pady=(0, 15))
        
        self.password_entry = ctk.CTkEntry(
            main_container,
            placeholder_text="Mot de passe de déchiffrement...",
            show="•",
            height=45,
            width=400,
            font=ctk.CTkFont(size=13),
            fg_color=COLORS["card"],
            border_color=COLORS["primary"],
            border_width=1
        )
        self.password_entry.pack(pady=(0, 10))
        
        self.output_button = ctk.CTkButton(
            main_container,
            text="📁 Choisir l'emplacement de sortie",
            command=self.choose_output_location,
            height=45,
            width=400,
            font=ctk.CTkFont(size=13),
            fg_color=COLORS["card"],
            hover_color=COLORS["hover"],
            text_color=COLORS["light"]
        )
        self.output_button.pack(pady=(0, 15))
        
        self.output_label = ctk.CTkLabel(
            main_container,
            text="Aucun emplacement sélectionné",
            font=ctk.CTkFont(size=11),
            text_color=COLORS["gray"],
            wraplength=400,
            justify="left"
        )
        self.output_label.pack(pady=(5, 15))
        
        button_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        button_frame.pack(fill="x", pady=(10, 10))
        
        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)
        
        ctk.CTkButton(
            button_frame,
            text="Annuler",
            command=self.cancel,
            fg_color=COLORS["gray_dark"],
            hover_color=COLORS["gray"],
            height=45,
            font=ctk.CTkFont(size=13),
            width=150
        ).grid(row=0, column=0, padx=(0, 10), sticky="e")
        
        self.ok_button = ctk.CTkButton(
            button_frame,
            text="Déchiffrer",
            command=self.ok,
            fg_color=COLORS["primary"],
            hover_color="#257399",
            height=45,
            font=ctk.CTkFont(size=13, weight="bold"),
            width=150,
            state="disabled"
        )
        self.ok_button.grid(row=0, column=1, sticky="w")
        
        self.password_entry.bind('<Return>', lambda e: self.ok() if self.ok_button.cget("state") == "normal" else None)
        self.bind('<Escape>', lambda e: self.cancel())
        
        self.protocol("WM_DELETE_WINDOW", self.cancel)
        
        self.after(100, self.focus_password_entry)
    
    def focus_password_entry(self):
        self.password_entry.focus()
    
    def clean_password_fields(self):
        if hasattr(self, 'password_entry'):
            self.password_entry.delete(0, 'end')
            self.password_entry.update()
    
    def choose_output_location(self):
        if self.original_filename.endswith('.enc'):
            default_name = self.original_filename[:-4]
        else:
            default_name = self.original_filename
        
        output_file = filedialog.asksaveasfilename(
            title="Choisir l'emplacement pour le fichier déchiffré",
            initialdir=Path.home(),
            initialfile=default_name,
            defaultextension="",
            filetypes=[("Tous les fichiers", "*.*")]
        )
        
        if output_file:
            self.output_path = Path(output_file)
            
            path_str = str(self.output_path)
            if len(path_str) > 50:
                display_path = "..." + path_str[-47:]
            else:
                display_path = path_str
            
            self.output_label.configure(
                text=f"Sortie : {display_path}",
                text_color=COLORS["light"]
            )
            self.check_ready()
    
    def check_ready(self):
        if self.password_entry.get() and self.output_path:
            self.ok_button.configure(state="normal")
        else:
            self.ok_button.configure(state="disabled")
    
    def ok(self):
        self.ok_button.configure(state="disabled")
        
        password = self.password_entry.get()
        if password and self.output_path:
            self.result = password
        
        self.clean_password_fields()
        
        if not self._destroyed:
            self._destroyed = True
            self.destroy()
    
    def cancel(self):
        self.clean_password_fields()
        
        if not self._destroyed:
            self._destroyed = True
            self.result = None
            self.destroy()
    
    def show(self):
        self.wait_window()
        return self.result, self.output_path

class EncryptPasswordDialog(ctk.CTkToplevel):
    def __init__(self, parent, filename=""):
        super().__init__(parent)
        
        self.title("Chiffrer un fichier")
        self.geometry("500x430")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        
        self.result = None
        self.delete_original = False
        self._destroyed = False
        
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (500 // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (400 // 2)
        self.geometry(f"500x430+{x}+{y}")
        
        self.configure(fg_color=COLORS["dark"])
        
        main_container = ctk.CTkFrame(self, fg_color=COLORS["dark"])
        main_container.pack(fill="both", expand=True, padx=25, pady=25)
        
        icon_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        icon_frame.pack(pady=(10, 15))
        
        ctk.CTkLabel(
            icon_frame,
            text="🔒",
            font=ctk.CTkFont(size=32),
            text_color=COLORS["primary"]
        ).pack()
        
        display_filename = filename
        if len(filename) > 40:
            display_filename = filename[:37] + "..."
        
        ctk.CTkLabel(
            main_container,
            text=f"Chiffrement de : {display_filename}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["light"],
            wraplength=450,
            justify="center"
        ).pack(pady=(0, 5))
        
        ctk.CTkLabel(
            main_container,
            text="Entrez le mot de passe pour le chiffrement",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["gray"]
        ).pack(pady=(0, 15))
        
        self.password_entry = ctk.CTkEntry(
            main_container,
            placeholder_text="Mot de passe de chiffrement...",
            show="•",
            height=45,
            width=400,
            font=ctk.CTkFont(size=13),
            fg_color=COLORS["card"],
            border_color=COLORS["primary"],
            border_width=1
        )
        self.password_entry.pack(pady=(0, 10))
        
        self.password_confirm = ctk.CTkEntry(
            main_container,
            placeholder_text="Confirmez le mot de passe...",
            show="•",
            height=45,
            width=400,
            font=ctk.CTkFont(size=13),
            fg_color=COLORS["card"],
            border_color=COLORS["primary"],
            border_width=1
        )
        self.password_confirm.pack(pady=(0, 20))
        
        self.delete_var = ctk.BooleanVar(value=False)
        self.delete_checkbox = ctk.CTkCheckBox(
            main_container,
            text="Supprimer le fichier original après chiffrement",
            variable=self.delete_var,
            font=ctk.CTkFont(size=12),
            fg_color=COLORS["primary"],
            hover_color="#257399"
        )
        self.delete_checkbox.pack(pady=(0, 25))
        
        button_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        button_frame.pack(fill="x", pady=(0, 10))
        
        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)
        
        ctk.CTkButton(
            button_frame,
            text="Annuler",
            command=self.cancel,
            fg_color=COLORS["gray_dark"],
            hover_color=COLORS["gray"],
            height=45,
            font=ctk.CTkFont(size=13),
            width=150
        ).grid(row=0, column=0, padx=(0, 10), sticky="e")
        
        self.ok_button = ctk.CTkButton(
            button_frame,
            text="Chiffrer",
            command=self.ok,
            fg_color=COLORS["primary"],
            hover_color="#257399",
            height=45,
            font=ctk.CTkFont(size=13, weight="bold"),
            width=150
        )
        self.ok_button.grid(row=0, column=1, sticky="w")
        
        self.password_entry.bind('<Return>', lambda e: self.password_confirm.focus())
        self.password_confirm.bind('<Return>', lambda e: self.ok())
        self.bind('<Escape>', lambda e: self.cancel())
        
        self.protocol("WM_DELETE_WINDOW", self.cancel)
        
        self.after(100, self.focus_password_entry)
    
    def focus_password_entry(self):
        self.password_entry.focus()
    
    def clean_password_fields(self):
        if hasattr(self, 'password_entry'):
            self.password_entry.delete(0, 'end')
            self.password_entry.update()
        if hasattr(self, 'password_confirm'):
            self.password_confirm.delete(0, 'end')
            self.password_confirm.update()
    
    def ok(self):
        self.ok_button.configure(state="disabled")
        
        password = self.password_entry.get()
        password_confirm = self.password_confirm.get()
        
        if not password:
            CTkMessagebox(
                title="Erreur",
                message="Le mot de passe ne peut pas être vide !",
                icon="cancel",
                width=500,
                height=180
            )
            self.ok_button.configure(state="normal")
            return
        
        if password != password_confirm:
            CTkMessagebox(
                title="Erreur",
                message="Les mots de passe ne correspondent pas !",
                icon="cancel",
                width=500,
                height=180
            )
            self.ok_button.configure(state="normal")
            self.clean_password_fields()
            self.password_entry.focus()
            return
        
        self.result = password
        self.delete_original = self.delete_var.get()
        
        self.clean_password_fields()
        
        if not self._destroyed:
            self._destroyed = True
            self.destroy()
    
    def cancel(self):
        self.clean_password_fields()
        
        if not self._destroyed:
            self._destroyed = True
            self.result = None
            self.destroy()
    
    def show(self):
        self.wait_window()
        return self.result, self.delete_original

class MasterPasswordDialog(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        
        self.title("Mot de passe maître")
        self.geometry("450x330")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        
        self.result = None
        self._destroyed = False
        
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (450 // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (330 // 2)
        self.geometry(f"450x330+{x}+{y}")
        
        self.configure(fg_color=COLORS["dark"])
        
        main_container = ctk.CTkFrame(self, fg_color=COLORS["dark"])
        main_container.pack(fill="both", expand=True, padx=25, pady=25)
        
        icon_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        icon_frame.pack(pady=(10, 15))
        
        ctk.CTkLabel(
            icon_frame,
            text="🔑",
            font=ctk.CTkFont(size=32),
            text_color=COLORS["primary"]
        ).pack()
        
        ctk.CTkLabel(
            main_container,
            text="Mot de passe maître",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["light"]
        ).pack(pady=(0, 5))
        
        ctk.CTkLabel(
            main_container,
            text="Ce mot de passe sera utilisé pour tous les fichiers",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["gray"]
        ).pack(pady=(0, 15))
        
        self.password_entry = ctk.CTkEntry(
            main_container,
            placeholder_text="Entrez le mot de passe maître...",
            show="•",
            height=45,
            width=350,
            font=ctk.CTkFont(size=13),
            fg_color=COLORS["card"],
            border_color=COLORS["primary"],
            border_width=1
        )
        self.password_entry.pack(pady=(0, 20))
        
        button_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        button_frame.pack(fill="x", pady=(0, 10))
        
        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)
        
        ctk.CTkButton(
            button_frame,
            text="Annuler",
            command=self.cancel,
            fg_color=COLORS["gray_dark"],
            hover_color=COLORS["gray"],
            height=45,
            font=ctk.CTkFont(size=13),
            width=150
        ).grid(row=0, column=0, padx=(0, 10), sticky="e")
        
        self.ok_button = ctk.CTkButton(
            button_frame,
            text="Activer",
            command=self.ok,
            fg_color=COLORS["primary"],
            hover_color="#257399",
            height=45,
            font=ctk.CTkFont(size=13, weight="bold"),
            width=150
        )
        self.ok_button.grid(row=0, column=1, sticky="w")
        
        self.password_entry.bind('<Return>', lambda e: self.ok())
        self.bind('<Escape>', lambda e: self.cancel())
        
        self.protocol("WM_DELETE_WINDOW", self.cancel)
        
        self.after(100, self.focus_password_entry)
    
    def focus_password_entry(self):
        self.password_entry.focus()
    
    def clean_password_fields(self):
        if hasattr(self, 'password_entry'):
            self.password_entry.delete(0, 'end')
            self.password_entry.update()
    
    def ok(self):
        password = self.password_entry.get()
        if password:
            self.result = password
            self.clean_password_fields()
            if not self._destroyed:
                self._destroyed = True
                self.destroy()
        else:
            CTkMessagebox(
                title="Erreur",
                message="Le mot de passe ne peut pas être vide !",
                icon="cancel",
                width=400,
                height=180
            )
    
    def cancel(self):
        self.clean_password_fields()
        
        if not self._destroyed:
            self._destroyed = True
            self.result = None
            self.destroy()
    
    def show(self):
        self.wait_window()
        return self.result

class DeletePasswordDialog(ctk.CTkToplevel):
    def __init__(self, parent, filename=""):
        super().__init__(parent)
        
        self.title("Confirmer la suppression")
        self.geometry("450x345")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        
        self.result = None
        self._destroyed = False
        
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (450 // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (345 // 2)
        self.geometry(f"450x345+{x}+{y}")
        
        self.configure(fg_color=COLORS["dark"])
        
        main_container = ctk.CTkFrame(self, fg_color=COLORS["dark"])
        main_container.pack(fill="both", expand=True, padx=25, pady=25)
        
        icon_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        icon_frame.pack(pady=(10, 15))
        
        ctk.CTkLabel(
            icon_frame,
            text="⚠️",
            font=ctk.CTkFont(size=32),
            text_color=COLORS["warning"]
        ).pack()
        
        display_name = filename
        if filename.endswith('.enc'):
            display_name = display_name[:-4]
        
        ctk.CTkLabel(
            main_container,
            text=f"Suppression de : {display_name}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["light"]
        ).pack(pady=(0, 5))
        
        ctk.CTkLabel(
            main_container,
            text="Cette action est IRRÉVERSIBLE !",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["danger"]
        ).pack(pady=(0, 5))
        
        ctk.CTkLabel(
            main_container,
            text="Entrez le mot de passe pour confirmer la suppression :",
            font=ctk.CTkFont(size=11),
            text_color=COLORS["gray"]
        ).pack(pady=(0, 15))
        
        self.password_entry = ctk.CTkEntry(
            main_container,
            placeholder_text="Mot de passe du fichier...",
            show="•",
            height=45,
            width=350,
            font=ctk.CTkFont(size=13),
            fg_color=COLORS["card"],
            border_color=COLORS["danger"],
            border_width=1
        )
        self.password_entry.pack(pady=(0, 20))
        
        button_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        button_frame.pack(fill="x", pady=(0, 10))
        
        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)
        
        ctk.CTkButton(
            button_frame,
            text="Annuler",
            command=self.cancel,
            fg_color=COLORS["gray_dark"],
            hover_color=COLORS["gray"],
            height=45,
            font=ctk.CTkFont(size=13),
            width=150
        ).grid(row=0, column=0, padx=(0, 10), sticky="e")
        
        self.delete_button = ctk.CTkButton(
            button_frame,
            text="🗑 Supprimer",
            command=self.confirm_delete,
            fg_color=COLORS["danger"],
            hover_color="#c82333",
            height=45,
            font=ctk.CTkFont(size=13, weight="bold"),
            width=150
        )
        self.delete_button.grid(row=0, column=1, sticky="w")
        
        self.password_entry.bind('<Return>', lambda e: self.confirm_delete())
        self.bind('<Escape>', lambda e: self.cancel())
        
        self.protocol("WM_DELETE_WINDOW", self.cancel)
        
        self.after(100, self.focus_password_entry)
    
    def focus_password_entry(self):
        self.password_entry.focus()
    
    def clean_password_fields(self):
        if hasattr(self, 'password_entry'):
            self.password_entry.delete(0, 'end')
            self.password_entry.update()
    
    def confirm_delete(self):
        self.delete_button.configure(state="disabled")
        
        password = self.password_entry.get()
        if password:
            self.result = password
        
        self.clean_password_fields()
        
        if not self._destroyed:
            self._destroyed = True
            self.destroy()
    
    def cancel(self):
        self.clean_password_fields()
        
        if not self._destroyed:
            self._destroyed = True
            self.result = None
            self.destroy()
    
    def show(self):
        self.wait_window()
        return self.result

# POPUP DE RECHIFFREMENT ET NETTOYAGE 
class CleanupPopup(ctk.CTkToplevel):
    def __init__(self, parent, temp_file_path: Path, encrypted_file_path: Path, password: SecureBuffer):
        super().__init__(parent)
        
        self.temp_file_path = temp_file_path
        self.encrypted_file_path = encrypted_file_path
        self.password = password
        self.result = "clean"  # "clean", "reencrypt"
        
        self.title("Rechiffrer et nettoyer")
        self.geometry("450x260")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (450 // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (260 // 2)
        self.geometry(f"450x260+{x}+{y}")
        
        self.configure(fg_color=COLORS["dark"])
        
        main_container = ctk.CTkFrame(self, fg_color=COLORS["dark"])
        main_container.pack(fill="both", expand=True, padx=20, pady=20)
        
        icon_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        icon_frame.pack(pady=(10, 15))
        
        ctk.CTkLabel(
            icon_frame,
            text="💾",
            font=ctk.CTkFont(size=32),
            text_color=COLORS["primary"]
        ).pack()
        
        # Nom court du fichier
        filename = temp_file_path.name
        if len(filename) > 35:
            display_name = filename[:32] + "..."
        else:
            display_name = filename
        
        ctk.CTkLabel(
            main_container,
            text=f"Fichier : {display_name}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["light"],
            wraplength=400,
            justify="center"
        ).pack(pady=(0, 10))
        
        ctk.CTkLabel(
            main_container,
            text="Souhaitez-vous rechiffrer les modifications\navant de nettoyer le fichier temporaire ?",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["gray"],
            justify="center"
        ).pack(pady=(0, 20))
        
        button_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        button_frame.pack(fill="x", pady=(0, 10))
        
        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)
        
        self.reencrypt_button = ctk.CTkButton(
            button_frame,
            text="Rechiffrer",
            command=self.reencrypt_and_clean,
            fg_color=COLORS["primary"],
            hover_color="#257399",
            height=45,
            font=ctk.CTkFont(size=13, weight="bold"),
            width=180
        )
        self.reencrypt_button.grid(row=0, column=0, padx=(0, 10), sticky="ew")
        
        self.close_button = ctk.CTkButton(
            button_frame,
            text="Fermer",
            command=self.close_and_clean,
            fg_color=COLORS["primary"],
            hover_color="#257399",
            height=45,
            font=ctk.CTkFont(size=13, weight="bold"),
            width=180
        )
        self.close_button.grid(row=0, column=1, sticky="ew")
        
        self.bind('<Escape>', lambda e: self.close_and_clean())
        self.protocol("WM_DELETE_WINDOW", self.close_and_clean)
    
    def reencrypt_and_clean(self):
        try:
            # Lire le contenu du fichier temporaire
            with open(self.temp_file_path, 'rb') as f:
                plaintext_data = f.read()
            
            # Préparer les paramètres de chiffrement
            salt = os.urandom(SALT_SIZE)
            nonce = os.urandom(NONCE_SIZE)
            params = {
                "MEMORY_COST": MEMORY_COST,
                "TIME_COST": TIME_COST,
                "PARALLELISM": PARALLELISM
            }
            
            # Dériver la clé
            salt_buffer = SecureBuffer(salt)
            key = derive_key(self.password, salt_buffer, params)
            
            # Chiffrer
            params_header = pack_crypto_params(MEMORY_COST, TIME_COST, PARALLELISM)
            associated_data = MAGIC + params_header
            
            plaintext = SecureBuffer(plaintext_data)
            ciphertext = encrypt_secure(plaintext, key, nonce, associated_data)
            
            # Écrire le fichier chiffré (écrase l'original)
            with open(self.encrypted_file_path, 'wb') as f:
                f.write(MAGIC)
                f.write(params_header)
                f.write(salt)
                f.write(nonce)
                f.write(bytes(ciphertext.get()))
            
            secure_list = SecureList([
                salt_buffer, key, plaintext, ciphertext
            ])
            secure_list.clear()
            
            # Supprimer le fichier temporaire de manière sécurisée
            TempFileManager.secure_delete(self.temp_file_path)
            
            self.result = "reencrypt"
            
        except Exception as e:
            SecureExceptionContext.clean_traceback()
            error_msg = SecureExceptionContext.generic_error_message()
            CTkMessagebox(
                title="Erreur",
                message=f"Erreur lors du rechiffrement :\n{error_msg}",
                icon="cancel",
                width=500,
                height=200
            )
            self.result = "clean"
        
        self.destroy()
    
    def close_and_clean(self):
        try:
            TempFileManager.secure_delete(self.temp_file_path)
        except Exception as e:
            print(f"Erreur lors de la suppression: {e}")
        
        self.result = "clean"
        self.destroy()
    
    def show(self):
        self.wait_window()
        return self.result

# Interface principale avec structure hiérarchique RÉCURSIVE
class FileListGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("🔐 ARGONEDIT")
        self.geometry("1000x836")
        self.minsize(800, 600)
        
        self.current_files = []
        self.file_items = []
        self._opening_file = None
        
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self.create_sidebar()
        self.create_main_content()
        
        self.refresh_file_list()
        self.center_window()
    
    def toggle_master_password(self):
        global MASTER_PASSWORD, MASTER_PASSWORD_ENABLED
        
        if MASTER_PASSWORD_ENABLED:
            # Désactiver directement
            MASTER_PASSWORD = None
            MASTER_PASSWORD_ENABLED = False
            self.update_master_password_ui()
        else:
            # Activer
            dialog = MasterPasswordDialog(self)
            password = dialog.show()
            
            if password:
                MASTER_PASSWORD = password
                MASTER_PASSWORD_ENABLED = True
                self.update_master_password_ui()
    
    def update_master_password_ui(self):
        if MASTER_PASSWORD_ENABLED:
            self.master_pwd_indicator.configure(text="🟢", text_color=COLORS["success"])
            self.master_pwd_status_label.configure(
                text="MDP maître : Actif",
                text_color=COLORS["success"]
            )
            self.master_pwd_button.configure(text="🔓 Désactiver le MDP maître")
        else:
            self.master_pwd_indicator.configure(text="⚫", text_color=COLORS["gray"])
            self.master_pwd_status_label.configure(
                text="MDP maître : Inactif",
                text_color=COLORS["gray"]
            )
            self.master_pwd_button.configure(text="🔑 Activer le MDP maître")
    
    def create_sidebar(self):
        sidebar = ctk.CTkFrame(self, width=250, corner_radius=0, fg_color=COLORS["sidebar"])
        sidebar.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)
        
        logo_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        logo_frame.pack(fill="x", padx=20, pady=(30, 20))
        
        ctk.CTkLabel(
            logo_frame,
            text="🔐",
            font=ctk.CTkFont(size=40),
            text_color=COLORS["primary"]
        ).pack()
        
        ctk.CTkLabel(
            logo_frame,
            text="ArgonEdit",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=COLORS["light"]
        ).pack(pady=(5, 0))
        
        ctk.CTkLabel(
            logo_frame,
            text="Éditeur Sécurisé",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["gray"]
        ).pack()
        
        ctk.CTkFrame(sidebar, height=2, fg_color=COLORS["gray_dark"]).pack(fill="x", padx=20, pady=20)

        stats_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        stats_frame.pack(fill="x", padx=20, pady=(0, 20))

        # Dossier
        ctk.CTkLabel(
            stats_frame,
            text="Dossier :",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["gray"]
        ).pack(anchor="w")

        self.dir_label = ctk.CTkLabel(
            stats_frame,
            text=self.get_display_path(TARGET_DIRECTORY),
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=COLORS["light"],
            wraplength=200,
            justify="left"
        )
        self.dir_label.pack(anchor="w", pady=(2, 15))

        # Nombre de fichiers
        self.file_count_label = ctk.CTkLabel(
            stats_frame,
            text="0 fichiers",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["light"]
        )
        self.file_count_label.pack(anchor="w")

        ctk.CTkLabel(
            stats_frame,
            text="fichiers chiffrés trouvés",
            font=ctk.CTkFont(size=11),
            text_color=COLORS["gray"]
        ).pack(anchor="w")
        
        ctk.CTkFrame(sidebar, height=2, fg_color=COLORS["gray_dark"]).pack(fill="x", padx=20, pady=20)
        
        button_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        button_frame.pack(fill="x", padx=20, pady=(0, 10))
        
        ctk.CTkButton(
            button_frame,
            text="🔄 Rafraîchir la liste",
            command=self.refresh_file_list,
            height=45,
            font=ctk.CTkFont(size=13),
            fg_color=COLORS["primary"],
            hover_color="#257399",
            text_color=COLORS["light"]
        ).pack(fill="x", pady=(0, 10))
        
        ctk.CTkButton(
            button_frame,
            text="📂 Changer de dossier",
            command=self.change_directory,
            height=45,
            font=ctk.CTkFont(size=13),
            fg_color=COLORS["primary"],
            hover_color="#257399",
            text_color=COLORS["light"]
        ).pack(fill="x")
        
        ctk.CTkFrame(sidebar, height=2, fg_color=COLORS["gray_dark"]).pack(fill="x", padx=20, pady=20)
        
        encrypt_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        encrypt_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        button_container = ctk.CTkFrame(encrypt_frame, fg_color="transparent")
        button_container.pack(expand=True, pady=(0, 10))
        
        self.encrypt_button = ctk.CTkButton(
            button_container,
            text="Chiffrer et envoyer au coffre",
            command=self.select_file_to_encrypt,
            height=50,
            font=ctk.CTkFont(size=13),
            fg_color=COLORS["primary"],
            text_color=COLORS["light"],
            hover_color="#a30b22",
            corner_radius=8,
            width=200
        )
        self.encrypt_button.pack(pady=5)
        
        CTkToolTip(self.encrypt_button, message="Sélectionner un fichier à chiffrer et l'envoyer au coffre-fort")
        
        self.decrypt_button = ctk.CTkButton(
            button_container,
            text="Déchiffrer un fichier",
            command=self.select_file_to_decrypt,
            height=50,
            font=ctk.CTkFont(size=13),
            fg_color=COLORS["primary"],
            text_color=COLORS["light"],
            hover_color="#05b044",
            corner_radius=8,
            width=200
        )
        self.decrypt_button.pack(pady=5)
        
        CTkToolTip(self.decrypt_button, message="Sélectionner un fichier .enc à déchiffrer et le sauvegarder")
        
        ctk.CTkFrame(sidebar, height=2, fg_color=COLORS["gray_dark"]).pack(fill="x", padx=20, pady=(20, 10))
        
        # Section Mot de passe maître
        master_pwd_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        master_pwd_frame.pack(fill="x", padx=20, pady=(0, 10))
        
        # Indicateur d'état
        status_frame = ctk.CTkFrame(master_pwd_frame, fg_color=COLORS["card"], corner_radius=8)
        status_frame.pack(fill="x", pady=(0, 10))
        
        self.master_pwd_indicator = ctk.CTkLabel(
            status_frame,
            text="⚫",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["gray"]
        )
        self.master_pwd_indicator.pack(side="left", padx=10, pady=8)
        
        self.master_pwd_status_label = ctk.CTkLabel(
            status_frame,
            text="MDP maître : Inactif",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["gray"]
        )
        self.master_pwd_status_label.pack(side="left", pady=8)
        
        # Bouton de gestion
        self.master_pwd_button = ctk.CTkButton(
            master_pwd_frame,
            text="🔑 Activer le MDP maître",
            command=self.toggle_master_password,
            height=45,
            font=ctk.CTkFont(size=13),
            fg_color=COLORS["primary"],
            hover_color="#257399",
            text_color=COLORS["light"]
        )
        self.master_pwd_button.pack(fill="x")
        
        CTkToolTip(self.master_pwd_button, message="Activer/désactiver le mot de passe maître pour tous les fichiers")
        
        ctk.CTkFrame(sidebar, height=2, fg_color=COLORS["gray_dark"]).pack(fill="x", padx=20, pady=(20, 10))
        
        footer_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        footer_frame.pack(fill="x", padx=20, pady=(10, 20))
    
    def select_file_to_encrypt(self, event=None):
        file_path = filedialog.askopenfilename(
            title="Sélectionner un fichier à chiffrer",
            filetypes=[("Tous les fichiers", "*.*")]
        )
        
        if file_path:
            self.process_file_for_encryption(Path(file_path))
    
    def select_file_to_decrypt(self, event=None):
        initial_dir = TARGET_DIRECTORY if TARGET_DIRECTORY.exists() else Path.home()
        
        file_path = filedialog.askopenfilename(
            title="Sélectionner un fichier à déchiffrer",
            initialdir=str(initial_dir),
            filetypes=[("Fichiers chiffrés", "*.enc"), ("Tous les fichiers", "*.*")]
        )
        
        if file_path:
            self.process_file_for_decryption(Path(file_path))
    
    def process_file_for_encryption(self, file_path: Path):
        if not file_path.exists():
            CTkMessagebox(
                title="Erreur",
                message="Le fichier sélectionné n'existe pas !",
                icon="cancel",
                width=500,
                height=180
            )
            return
        
        if file_path.suffix == '.enc':
            CTkMessagebox(
                title="Avertissement",
                message="Ce fichier est déjà chiffré (.enc).\nChoisissez un fichier non chiffré.",
                icon="warning",
                width=500,
                height=200
            )
            return
        
        dialog = EncryptPasswordDialog(self, filename=file_path.name)
        password, delete_original = dialog.show()
        
        if not password:
            return
        
        output_path = TARGET_DIRECTORY / (file_path.name + '.enc')
        if output_path.exists():
            response = CTkMessagebox(
                title="Fichier existant",
                message=f"Un fichier chiffré existe déjà.\nVoulez-vous le remplacer ?",
                icon="warning",
                option_1="Annuler",
                option_2="Remplacer",
                width=500,
                height=200
            ).get()
            
            if response != "Remplacer":
                return
        
        try:
            progress_msg = CTkMessagebox(
                title="Chiffrement en cours",
                message="Chiffrement du fichier...\nVeuillez patienter.",
                icon="info",
                width=500,
                height=180
            )
            self.update()
            
            success = encrypt_file(
                file_path, 
                password, 
                TARGET_DIRECTORY, 
                delete_original
            )
            
            try:
                progress_msg.destroy()
            except:
                pass
            
            if success:
                CTkMessagebox(
                    title="Succès",
                    message="Fichier chiffré avec succès !",
                    icon="check",
                    width=500,
                    height=200
                ).get()
                self.refresh_file_list()
            else:
                CTkMessagebox(
                    title="Erreur",
                    message="Échec du chiffrement du fichier",
                    icon="cancel",
                    width=500,
                    height=180
                )
                
        except Exception as e:
            SecureExceptionContext.clean_traceback()
            CTkMessagebox(
                title="Erreur",
                message="Erreur lors du chiffrement.",
                icon="cancel",
                width=500,
                height=200
            )
    
    def process_file_for_decryption(self, file_path: Path):
        if not file_path.exists():
            CTkMessagebox(
                title="Erreur",
                message="Le fichier sélectionné n'existe pas !",
                icon="cancel",
                width=500,
                height=180
            )
            return
        
        if file_path.suffix != '.enc':
            response = CTkMessagebox(
                title="Avertissement",
                message="Ce fichier n'a pas l'extension .enc.\nVoulez-vous quand même essayer de le déchiffrer ?",
                icon="warning",
                option_1="Annuler",
                option_2="Continuer",
                width=500,
                height=200
            ).get()
            
            if response != "Continuer":
                return
        
        dialog = DecryptToFileDialog(self, filename=file_path.name)
        result = dialog.show()
        
        if not result or not result[0]:
            return
        
        password, output_path = result
        
        if not password or not output_path:
            return
        
        try:
            progress_msg = CTkMessagebox(
                title="Déchiffrement en cours",
                message="Déchiffrement du fichier...\nVeuillez patienter.",
                icon="info",
                width=500,
                height=180
            )
            self.update()
            
            success = decrypt_file_to_disk(file_path, password, output_path)
            
            try:
                progress_msg.destroy()
            except:
                pass
            
            if success:
                CTkMessagebox(
                    title="Succès",
                    message="Fichier déchiffré avec succès !",
                    icon="check",
                    width=500,
                    height=200
                ).get()
            else:
                CTkMessagebox(
                    title="Erreur",
                    message="Échec du déchiffrement du fichier\n\nVérifiez que le mot de passe est correct.",
                    icon="cancel",
                    width=500,
                    height=200
                )
                
        except Exception as e:
            SecureExceptionContext.clean_traceback()
            CTkMessagebox(
                title="Erreur",
                message="Erreur lors du déchiffrement.",
                icon="cancel",
                width=500,
                height=200
            )
    
    def get_display_path(self, path):
        path_str = str(path)
        if len(path_str) > 30:
            return "..." + path_str[-27:]
        return path_str
    
    def create_main_content(self):
        main_content = ctk.CTkFrame(self, corner_radius=0, fg_color=COLORS["darker"])
        main_content.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        main_content.grid_columnconfigure(0, weight=1)
        main_content.grid_rowconfigure(1, weight=1)
        
        search_frame = ctk.CTkFrame(main_content, fg_color="transparent")
        search_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=20)
        search_frame.grid_columnconfigure(0, weight=1)
        
        self.search_entry = ctk.CTkEntry(
            search_frame,
            placeholder_text="Rechercher un fichier... (tapez pour filtrer)",
            height=45,
            font=ctk.CTkFont(size=13),
            fg_color=COLORS["card"],
            border_color=COLORS["primary"],
            border_width=1
        )
        self.search_entry.grid(row=0, column=0, sticky="ew")
        self.search_entry.bind("<KeyRelease>", self.filter_files)
        
        list_container = ctk.CTkFrame(main_content, corner_radius=0, fg_color=COLORS["darker"])
        list_container.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        list_container.grid_columnconfigure(0, weight=1)
        list_container.grid_rowconfigure(0, weight=1)
        
        self.canvas = ctk.CTkCanvas(
            list_container,
            bg=COLORS["darker"],
            highlightthickness=0
        )
        self.canvas.grid(row=0, column=0, sticky="nsew")
        
        self.scrollbar = ctk.CTkScrollbar(
            list_container,
            orientation="vertical",
            command=self.canvas.yview
        )
        self.scrollbar.grid(row=0, column=1, sticky="ns")
        
        self.inner_frame = ctk.CTkFrame(self.canvas, fg_color=COLORS["darker"])
        self.inner_frame_id = self.canvas.create_window(
            (0, 0),
            window=self.inner_frame,
            anchor="nw",
            width=self.canvas.winfo_width()
        )
        
        self.inner_frame.bind("<Configure>", self.on_frame_configure)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.bind("<Configure>", self.on_canvas_configure)
        self.canvas.bind_all("<MouseWheel>", self.on_mousewheel)
    
    def on_frame_configure(self, event=None):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
    
    def on_canvas_configure(self, event):
        canvas_width = event.width
        self.canvas.itemconfig(self.inner_frame_id, width=canvas_width)
    
    def on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
    
    def center_window(self):
        self.update_idletasks()
        width = 1000
        height = 836
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
    
    def change_directory(self):
        global TARGET_DIRECTORY
        
        new_dir = filedialog.askdirectory(
            title="Sélectionner un dossier",
            initialdir=str(TARGET_DIRECTORY)
        )
        
        if new_dir:
            TARGET_DIRECTORY = Path(new_dir)
            self.dir_label.configure(text=self.get_display_path(TARGET_DIRECTORY))
            self.refresh_file_list()
    
    def refresh_file_list(self):
        for widget in self.inner_frame.winfo_children():
            widget.destroy()
    
        self.file_items = []
    
        if not TARGET_DIRECTORY.exists():
            CTkMessagebox(
                title="Erreur",
                message="Le dossier cible n'existe pas !",
                icon="cancel",
                width=500,
                height=180
            )
            self.file_count_label.configure(text="0 fichiers")
            return
    
        try:
            all_files = sorted(TARGET_DIRECTORY.rglob("*.enc"))
        
            if not all_files:
                empty_frame = ctk.CTkFrame(self.inner_frame, fg_color=COLORS["darker"], height=200)
                empty_frame.pack(fill="x", expand=True, pady=100)
            
                ctk.CTkLabel(
                    empty_frame,
                    text="🔭",
                    font=ctk.CTkFont(size=60),
                    text_color=COLORS["gray"]
                ).pack()
            
                ctk.CTkLabel(
                    empty_frame,
                    text="Aucun fichier chiffré trouvé",
                    font=ctk.CTkFont(size=16, weight="bold"),
                    text_color=COLORS["light"]
                ).pack(pady=(20, 10))
            
                self.file_count_label.configure(text="0 fichiers")
            else:
                files_by_folder = {}
                for file_path in all_files:
                    parent = file_path.parent
                    if parent not in files_by_folder:
                        files_by_folder[parent] = []
                    files_by_folder[parent].append(file_path)
                
                folder_hierarchy = {}
                for folder in files_by_folder.keys():
                    parent = folder.parent
                    if parent not in folder_hierarchy:
                        folder_hierarchy[parent] = []
                    folder_hierarchy[parent].append(folder)
                
                def create_folder_structure(parent_path, container, depth=0):
                    if parent_path in files_by_folder:
                        for idx, file_path in enumerate(files_by_folder[parent_path]):
                            file_item = FileListItem(
                                container,
                                file_path.name,
                                idx + 1,
                                command=self.open_file,
                                download_command=self.download_file,
                                delete_command=self.delete_file
                            )
                            file_item.pack(fill="x", pady=2, padx=(depth * 20, 0))
                            self.file_items.append(file_item)
    
                    if parent_path in folder_hierarchy:
                        for subfolder in sorted(folder_hierarchy[parent_path]):
                            if subfolder in files_by_folder:
                                folder_item = FolderItem(container, subfolder, len(files_by_folder[subfolder]))
                                folder_item.pack(fill="x", pady=2, padx=(depth * 20, 0))
                
                                content_container = ctk.CTkFrame(container, fg_color="transparent")
                                content_container.pack(fill="x")
                                folder_item.content_container = content_container
                
                                create_folder_structure(subfolder, content_container, depth + 1)
                
                                content_container.pack_forget()
                
                create_folder_structure(TARGET_DIRECTORY, self.inner_frame)
            
                self.file_count_label.configure(text=f"{len(all_files)} fichier(s)")
        
            self.current_files = all_files
        
        except Exception as e:
            SecureExceptionContext.clean_traceback()
            CTkMessagebox(
                title="Erreur",
                message="Impossible de lire le dossier.",
                icon="cancel",
                width=500,
                height=200
            )
    
    def filter_files(self, event=None):
        search_term = self.search_entry.get().lower()
        
        for file_item in self.file_items:
            display_name = file_item.filename
            if display_name.endswith('.enc'):
                display_name = display_name[:-4]
                
            if search_term in display_name.lower():
                file_item.pack(fill="x", pady=2)
            else:
                file_item.pack_forget()
            self.canvas.yview_moveto(0)
    
    def download_file(self, filename):
        try:
            file_path = next(p for p in self.current_files if p.name == filename)
            
            if not file_path.exists():
                CTkMessagebox(
                    title="Erreur",
                    message="Fichier introuvable !",
                    icon="cancel",
                    width=500,
                    height=180
                )
                return
            
            password = None
            
            # Essayer d'abord avec le mot de passe maître
            if MASTER_PASSWORD_ENABLED and MASTER_PASSWORD:
                try:
                    file_info = read_encrypted_file(file_path)
                    password_buffer = SecureBuffer(MASTER_PASSWORD.encode('utf-8'))
                    
                    key = derive_key(password_buffer, file_info["salt"], file_info["params"])
                    # Test de déchiffrement
                    plaintext = decrypt_secure(
                        file_info["ciphertext"],
                        key,
                        file_info["nonce"],
                        file_info["associated_data"]
                    )
                    password = MASTER_PASSWORD
                    plaintext.clear()
                    key.clear()
                    password_buffer.clear()
                    
                except Exception:
                    # Le MDP maître n'a pas fonctionné
                    password = None
            
            # Si le MDP maître n'a pas fonctionné, demander le mot de passe
            if password is None:
                password_dialog = PasswordDialog(self, filename=filename)
                password_buffer = password_dialog.show()
                
                if not password_buffer:
                    return
                
                password = password_buffer.execute_with_bytes(lambda x: x.decode('utf-8'))
                password_buffer.clear()
            
            # Demander l'emplacement de sauvegarde
            default_name = filename[:-4] if filename.endswith('.enc') else filename
            
            output_file = filedialog.asksaveasfilename(
                title="Choisir l'emplacement pour le fichier déchiffré",
                initialdir=Path.home(),
                initialfile=default_name,
                defaultextension="",
                filetypes=[("Tous les fichiers", "*.*")]
            )
            
            if not output_file:
                return
            
            output_path = Path(output_file)
            
            # Déchiffrer le fichier
            progress_msg = CTkMessagebox(
                title="Déchiffrement en cours",
                message="Déchiffrement du fichier...\nVeuillez patienter.",
                icon="info",
                width=500,
                height=180
            )
            self.update()
            
            success = decrypt_file_to_disk(file_path, password, output_path)
            
            try:
                progress_msg.destroy()
            except:
                pass
            
            if success:
                CTkMessagebox(
                    title="Succès",
                    message="Fichier déchiffré avec succès !",
                    icon="check",
                    width=500,
                    height=200
                ).get()
            else:
                CTkMessagebox(
                    title="Erreur",
                    message="Échec du déchiffrement du fichier\n\nVérifiez que le mot de passe est correct.",
                    icon="cancel",
                    width=500,
                    height=200
                )
                
        except StopIteration:
            CTkMessagebox(
                title="Erreur",
                message="Fichier introuvable dans la liste !",
                icon="cancel",
                width=500,
                height=180
            )
        except Exception as e:
            SecureExceptionContext.clean_traceback()
            CTkMessagebox(
                title="Erreur",
                message="Erreur lors du déchiffrement.",
                icon="cancel",
                width=500,
                height=200
            )
    
    def delete_file(self, filename):
        try:
        # Trouver le chemin du fichier
            file_path = next(p for p in self.current_files if p.name == filename)
        
            if not file_path.exists():
                CTkMessagebox(
                    title="Erreur",
                    message="Fichier introuvable !",
                    icon="cancel",
                    width=500,
                    height=180
                )
                return
        
        # Demander confirmation avec mot de passe
            dialog = DeletePasswordDialog(self, filename=filename)
            entered_password = dialog.show()
        
            if not entered_password:
                return  # Utilisateur a annulé
        
        # Vérifier le mot de passe
            if not verify_file_password(file_path, entered_password):
                CTkMessagebox(
                    title="Mot de passe incorrect",
                    message="Le mot de passe est incorrect !\n\nLa suppression a été annulée.",
                    icon="cancel",
                    width=500,
                    height=200
                )
                return
        
        # Confirmation finale
            response = CTkMessagebox(
                title="Dernière confirmation",
                message=f"Êtes-vous SÛR de vouloir supprimer ce fichier ?\n\nLe fichier sera définitivement supprimé !",
                icon="warning",
                option_1="Annuler",
                option_2="SUPPRIMER",
                width=550,
                height=220
            ).get()
        
            if response != "SUPPRIMER":
                return
        
            # Supprimer le fichier
            try:
                file_path.unlink()
            
            # Afficher un message de succès
                CTkMessagebox(
                    title="Succès",
                    message="Fichier supprimé définitivement !",
                    icon="check",
                width=500,
                    height=200
                ).get()
            
            # Rafraîchir la liste
                self.refresh_file_list()
            
            except Exception as e:
                SecureExceptionContext.clean_traceback()
                CTkMessagebox(
                    title="Erreur",
                    message="Impossible de supprimer le fichier.",
                    icon="cancel",
                    width=500,
                    height=200
                )
            
        except StopIteration:
            CTkMessagebox(
                title="Erreur",
                message="Fichier introuvable dans la liste !",
                icon="cancel",
                width=500,
                height=180
            )
        except Exception as e:
            SecureExceptionContext.clean_traceback()
            CTkMessagebox(
                title="Erreur",
                message="Erreur lors de la suppression.",
                icon="cancel",
                width=500,
                height=200
            )

    
    def open_file(self, filename):
        """Ouvre un fichier """
        if self._opening_file == filename:
            return
        self._opening_file = filename
        
        try:
            file_path = next(p for p in self.current_files if p.name == filename)
            
            if not file_path.exists():
                CTkMessagebox(
                    title="Erreur",
                    message="Fichier introuvable !",
                    icon="cancel",
                    width=500,
                    height=180
                )
                return
            
            password = None
            file_info = None
            plaintext = None
            key = None
            
            # Essayer d'abord avec le mot de passe maître
            if MASTER_PASSWORD_ENABLED and MASTER_PASSWORD:
                try:
                    file_info = read_encrypted_file(file_path)
                    password = SecureBuffer(MASTER_PASSWORD.encode('utf-8'))
                    
                    key = derive_key(password, file_info["salt"], file_info["params"])
                    plaintext = decrypt_secure(
                        file_info["ciphertext"],
                        key,
                        file_info["nonce"],
                        file_info["associated_data"]
                    )
                    
                except Exception:
                    if password:
                        password.clear()
                    if key:
                        key.clear()
                    password = None
                    file_info = None
                    plaintext = None
                    key = None
            
            # Si le MDP maître n'a pas fonctionné, demander le mot de passe
            if password is None:
                password_dialog = PasswordDialog(self, filename=filename)
                password = password_dialog.show()
                
                if not password:
                    self._opening_file = None
                    return
                
                # Déchiffrer avec le mot de passe saisi
                try:
                    file_info = read_encrypted_file(file_path)
                    key = derive_key(password, file_info["salt"], file_info["params"])
                    plaintext = decrypt_secure(
                        file_info["ciphertext"],
                        key,
                        file_info["nonce"],
                        file_info["associated_data"]
                    )
                except Exception as e:
                    CTkMessagebox(
                        title="Échec",
                        message="Impossible d'ouvrir le fichier (mot de passe incorrect ou fichier corrompu)",
                        icon="cancel",
                        width=500,
                        height=180
                    )
                    password.clear()
                    self._opening_file = None
                    return
            
            content_bytes = plaintext.execute_with_bytes(lambda x: x)
            
            try:
                content = content_bytes.decode('utf-8')
                plaintext.clear()
                key.clear()
                EditorWindow(self, file_path, content, file_info, password)
                
            except UnicodeDecodeError:
                # Fichier binaire - CONSERVER L'EXTENSION ORIGINALE
                # 1. Enlever '.enc' si présent
                original_name = filename
                if original_name.endswith('.enc'):
                    original_name = original_name[:-4]  # retire ".enc"
    
                # 2. Extraire l'extension originale
                original_path = Path(original_name)
                original_stem = original_path.stem  # Nom sans extension
                original_suffix = original_path.suffix  # Extension (.txt, .pdf, etc.)
    
                # 3. Nettoyer seulement le nom de base
                clean_stem = TempFileManager.clean_filename(original_stem)
    
                # 4. Reconstruire avec l'extension originale
                if original_suffix:
                    clean_name = f"{clean_stem}{original_suffix}"
                else:
                    clean_name = clean_stem  # Pas d'extension
    
                # 5. Créer un fichier temporaire avec le nom complet (nom + extension)
                # Utilise TempFileManager mais assure-toi qu'il garde l'extension
                temp_file_path = Path(tempfile.gettempdir()) / clean_name
    
                # 6. Éviter les collisions
                counter = 1
                while temp_file_path.exists():
                    if original_suffix:
                        temp_filename = f"{clean_stem}_{counter}{original_suffix}"
                    else:
                        temp_filename = f"{clean_stem}_{counter}"
                    temp_file_path = Path(tempfile.gettempdir()) / temp_filename
                    counter += 1
    
                # 7. Écrire le fichier
                with open(temp_file_path, 'wb') as f:
                    f.write(content_bytes)
                
                TempFileManager.open_with_default_app(temp_file_path)
                
                cleanup_popup = CleanupPopup(self, temp_file_path, file_path, password)
                result = cleanup_popup.show()
                
                if result == "reencrypt":
                    CTkMessagebox(
                        title="Succès",
                        message="Fichier rechiffré avec succès !",
                        icon="check",
                        width=500,
                        height=180
                    )
                    self.refresh_file_list()
                
                plaintext.clear()
                key.clear()
                
        finally:
            self.after(1000, lambda: setattr(self, '_opening_file', None))

# Classes restantes (modifiées pour la structure hiérarchique)
class FolderItem(ctk.CTkFrame):
    def __init__(self, master, folder_path, file_count):
        super().__init__(master, height=50, corner_radius=8, fg_color=COLORS["darker"])
        
        self.folder_path = folder_path
        self.expanded = False
        self.child_items = []
        self.content_container = None  # Conteneur pour fichiers + sous-dossiers
        
        self.toggle_button = ctk.CTkButton(
            self,
            text="▶",
            width=30,
            height=30,
            command=self.toggle,
            fg_color=COLORS["card"],
            hover_color=COLORS["hover"],
            corner_radius=4
        )
        self.toggle_button.grid(row=0, column=0, padx=10, pady=10)
        
        # Icône dossier
        ctk.CTkLabel(
            self,
            text="📁",
            font=ctk.CTkFont(size=18),
            width=30
        ).grid(row=0, column=1, padx=(0, 8), pady=10)
        
        folder_name = folder_path.name if folder_path != TARGET_DIRECTORY else "Racine"
        ctk.CTkLabel(
            self,
            text=folder_name,  # CHANGÉ : Juste le nom, pas "(X fichiers)"
            font=ctk.CTkFont(weight="bold", size=13),
            anchor="w"
        ).grid(row=0, column=2, padx=5, pady=10, sticky="w")
        
        self.grid_columnconfigure(2, weight=1)
    
    def toggle(self):
        self.expanded = not self.expanded
        
        if self.expanded:
            self.toggle_button.configure(text="▼")
            # Afficher le conteneur des fichiers ET sous-dossiers
            if self.content_container:
                self.content_container.pack(fill="x", after=self)
        else:
            self.toggle_button.configure(text="▶")
            # Cacher le conteneur (donc tous ses enfants : fichiers + sous-dossiers)
            if self.content_container:
                self.content_container.pack_forget()

class FileListItem(ctk.CTkFrame):
    def __init__(self, master, filename, index, command=None, download_command=None, delete_command=None):
        super().__init__(master, height=50, corner_radius=8, fg_color=COLORS["darker"])
        
        self.filename = filename
        self.command = command
        self.download_command = download_command
        self.delete_command = delete_command
        self.normal_color = COLORS["darker"]
        self._click_time = 0
        
        self.grid_columnconfigure(1, weight=1)
        
        display_name = filename
        if filename.endswith('.enc'):
            display_name = display_name[:-4]
        
        extension = Path(display_name).suffix.lower()
        icon_map = {
            '.txt': '📄', '.md': '📝', '.py': '🐍', '.js': '📜',
            '.html': '🌐', '.css': '🎨', '.json': '📋', '.xml': '📊',
            '.pdf': '📕', '.doc': '📘', '.docx': '📘',
            '.xls': '📗', '.xlsx': '📗', '.ppt': '📊', '.pptx': '📊',
            '.jpg': '🖼', '.jpeg': '🖼', '.png': '🖼', '.gif': '🖼',
            '.bmp': '🖼', '.tiff': '🖼',
            '.zip': '📦', '.rar': '📦', '.7z': '📦',
            '.mp3': '🎵', '.mp4': '🎬', '.avi': '🎬', '.mkv': '🎬'
        }
        icon = icon_map.get(extension, '📄')
        
        self.icon_label = ctk.CTkLabel(
            self, 
            text=icon,
            font=ctk.CTkFont(size=18),
            width=30
        )
        self.icon_label.grid(row=0, column=0, padx=(10, 8), pady=8, sticky="w")
        
        info_frame = ctk.CTkFrame(self, fg_color="transparent")
        info_frame.grid(row=0, column=1, padx=5, pady=8, sticky="ew")
        info_frame.grid_columnconfigure(0, weight=1)
        
        ctk.CTkLabel(
            info_frame,
            text=display_name,
            font=ctk.CTkFont(weight="bold", size=13),
            anchor="w"
        ).grid(row=0, column=0, sticky="w")
        
        # Frame pour les boutons d'action
        if command or download_command or delete_command:
            button_container = ctk.CTkFrame(self, fg_color="transparent")
            button_container.grid(row=0, column=2, padx=(5, 10), pady=8, sticky="e")
            
            if command:
                self.action_button = ctk.CTkButton(
                    button_container,
                    text="Ouvrir",
                    width=70,
                    height=26,
                    font=ctk.CTkFont(size=11),
                    command=self._open_file_safe
                )
                self.action_button.pack(side="left", padx=(0, 5))
            
            if download_command:
                self.download_button = ctk.CTkButton(
                    button_container,
                    text="⬇",
                    width=35,
                    height=26,
                    font=ctk.CTkFont(size=14),
                    command=self._download_file_safe,
                    fg_color=COLORS["success"],
                    hover_color="#0d7a3a"
                )
                self.download_button.pack(side="left", padx=(0, 5))
                CTkToolTip(self.download_button, message="Déchiffrer et sauvegarder")
            
            if delete_command:
                self.delete_button = ctk.CTkButton(
                    button_container,
                    text="🗑",
                    width=35,
                    height=26,
                    font=ctk.CTkFont(size=14),
                    command=self._delete_file_safe,
                    fg_color=COLORS["danger"],
                    hover_color="#c82333",
                    text_color=COLORS["lighter"]
                )
                self.delete_button.pack(side="left")
                CTkToolTip(self.delete_button, message="Supprimer le fichier")
        
        self.bind_hover_recursive(self)
        self.bind_double_click_recursive(self)
    
    def bind_hover_recursive(self, widget):
        widget.bind("<Enter>", self.on_enter, add="+")
        widget.bind("<Leave>", self.on_leave, add="+")
        
        for child in widget.winfo_children():
            self.bind_hover_recursive(child)
    
    def bind_double_click_recursive(self, widget):
        if hasattr(self, 'action_button') and widget == self.action_button:
            return
        if hasattr(self, 'download_button') and widget == self.download_button:
            return
        if hasattr(self, 'delete_button') and widget == self.delete_button:
            return
            
        widget.bind("<Double-Button-1>", self.on_double_click, add="+")
        
        for child in widget.winfo_children():
            self.bind_double_click_recursive(child)
    
    def on_enter(self, e):
        self.configure(fg_color=COLORS["hover"])
    
    def on_leave(self, e):
        self.configure(fg_color=self.normal_color)
    
    def _open_file_safe(self):
        current_time = time.time()
        if current_time - self._click_time > 0.5:
            self._click_time = current_time
            if self.command:
                self.command(self.filename)
    
    def _download_file_safe(self):
        current_time = time.time()
        if current_time - self._click_time > 0.5:
            self._click_time = current_time
            if self.download_command:
                self.download_command(self.filename)
    
    def _delete_file_safe(self):
        current_time = time.time()
        if current_time - self._click_time > 0.5:
            self._click_time = current_time
            if self.delete_command:
                self.delete_command(self.filename)
    
    def on_double_click(self, e):
        self._open_file_safe()

class EditorWindow(ctk.CTkToplevel):
    def __init__(self, parent, file_path: Path, content: str, file_info: dict, password: SecureBuffer):
        super().__init__(parent)
        
        self.file_path = file_path
        self.file_info = file_info
        self.password = password
        self.modified = False
        
        display_name = file_path.name
        if display_name.endswith('.enc'):
            display_name = display_name[:-4]
        
        self.title(f"Éditeur - {display_name}")
        self.geometry("1200x800")
        
        self.line_count = 1
        self.char_count = len(content)
        self.word_count = len(content.split())
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        self.search_matches = []
        self.search_index = 0
        
        self.create_toolbar()
        self.create_editor(content)
        self.create_searchbar()
        self.create_statusbar()
        
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.center_window(parent)
        self.lift()  # Passer au premier plan
        self.focus_force()  # Forcer le focus
        self.attributes('-topmost', True)  # Temporairement au-dessus
        self.after(100, lambda: self.attributes('-topmost', False))  # Enlever après 100ms
    
    def create_toolbar(self):
        toolbar = ctk.CTkFrame(self, height=70, corner_radius=0)
        toolbar.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        toolbar.grid_columnconfigure(1, weight=1)
        
        ctk.CTkButton(
            toolbar,
            text="← Fermer",
            width=100,
            height=40,
            command=self.on_closing,
            font=ctk.CTkFont(size=12)
        ).grid(row=0, column=0, padx=20, pady=15, sticky="w")
        
        title_frame = ctk.CTkFrame(toolbar, fg_color="transparent")
        title_frame.grid(row=0, column=1, padx=20, pady=15, sticky="w")
        
        display_name = self.file_path.name
        if display_name.endswith('.enc'):
            display_name = display_name[:-4]
        
        ctk.CTkLabel(
            title_frame,
            text=display_name,
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(anchor="w")
        
        file_stats = f"{self.char_count:,} caractères • {self.word_count:,} mots"
        ctk.CTkLabel(
            title_frame,
            text=file_stats,
            font=ctk.CTkFont(size=11),
            text_color=COLORS["gray"]
        ).pack(anchor="w", pady=(2, 0))
        
        button_frame = ctk.CTkFrame(toolbar, fg_color="transparent")
        button_frame.grid(row=0, column=2, padx=20, pady=15, sticky="e")
        
        self.save_button = ctk.CTkButton(
            button_frame,
            text="💾 Sauvegarder",
            width=120,
            height=40,
            command=self.save_file,
            font=ctk.CTkFont(size=12, weight="bold"),
            state="disabled"
        )
        self.save_button.pack(side="right", padx=(10, 0))
        
        CTkToolTip(self.save_button, message="Sauvegarder et rechiffrer le fichier")
    
    def create_editor(self, content):
        editor_frame = ctk.CTkFrame(self, corner_radius=0)
        editor_frame.grid(row=1, column=0, sticky="nsew", padx=0, pady=0)
        editor_frame.grid_columnconfigure(0, weight=1)
        editor_frame.grid_rowconfigure(0, weight=1)
        
        self.text_scrollbar = ctk.CTkScrollbar(editor_frame)
        self.text_scrollbar.grid(row=0, column=1, sticky="ns")

        # Scrollmap : fine bande à droite de la scrollbar
        self.scrollmap = tk.Canvas(
            editor_frame,
            width=10,
            bg="#1a1a1a",
            highlightthickness=0,
            cursor="hand2"
        )
        self.scrollmap.grid(row=0, column=2, sticky="ns", padx=(0, 4))
        self.scrollmap.bind("<Button-1>", self._scrollmap_click)
        
        self.text_widget = ctk.CTkTextbox(
            editor_frame,
            wrap="word",
            font=ctk.CTkFont(family="Consolas", size=14),
            scrollbar_button_color=COLORS["primary"],
            border_width=0,
            fg_color=COLORS["editor_bg"],
            text_color=COLORS["editor_fg"],
            activate_scrollbars=False
        )
        self.text_widget.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        
        self.text_widget.configure(yscrollcommand=self.text_scrollbar.set)
        self.text_scrollbar.configure(command=self.text_widget.yview)
        
        self.text_widget.insert("1.0", content)
        self.text_widget.edit_modified(False)
        
        self.setup_context_menu()
        self.text_widget.bind("<<Modified>>", self.on_text_modified)    
    def setup_context_menu(self):
        self.context_menu = ctk.CTkFrame(
            self.text_widget,
            width=150,
            height=40,
            corner_radius=6,
            fg_color=COLORS["card"],
            border_width=1,
            border_color=COLORS["gray_dark"]
        )
        
        copy_button = ctk.CTkButton(
            self.context_menu,
            text="Copier",
            width=140,
            height=30,
            corner_radius=4,
            font=ctk.CTkFont(size=12),
            fg_color="transparent",
            hover_color=COLORS["hover"],
            command=self.copy_selected_text,
            anchor="w"
        )
        copy_button.pack(padx=5, pady=5, fill="x")
        
        self.context_menu.place_forget()
        self.text_widget.bind("<Button-3>", self.show_context_menu)
        self.text_widget.bind("<Button-1>", self.hide_context_menu)
        self.text_widget.bind("<Control-c>", lambda e: self.copy_selected_text())
    
    def show_context_menu(self, event):
        x = self.text_widget.winfo_rootx() + event.x
        y = self.text_widget.winfo_rooty() + event.y
        
        self.context_menu.place(x=event.x, y=event.y)
        self.context_menu.lift()
        
        return "break"
    
    def hide_context_menu(self, event):
        self.context_menu.place_forget()
    
    def copy_selected_text(self):
        try:
            if self.text_widget.tag_ranges("sel"):
                selected_text = self.text_widget.get("sel.first", "sel.last")
                self.text_widget.clipboard_clear()
                self.text_widget.clipboard_append(selected_text)
            
            self.hide_context_menu(None)
        except Exception:
            pass
    
    def create_searchbar(self):
        self.search_frame = ctk.CTkFrame(self, height=50, corner_radius=0, fg_color=COLORS["sidebar"])
        self.search_frame.grid(row=2, column=0, sticky="ew", padx=0, pady=0)
        self.search_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            self.search_frame,
            text="🔍 Rechercher :",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["gray"]
        ).grid(row=0, column=0, padx=(15, 5), pady=10)

        # Groupe : champ + boutons inline
        search_input_frame = ctk.CTkFrame(self.search_frame, fg_color="transparent")
        search_input_frame.grid(row=0, column=1, padx=5, pady=10, sticky="w")

        self.search_entry = ctk.CTkEntry(
            search_input_frame,
            placeholder_text="Terme à rechercher...",
            width=250,
            height=30,
            font=ctk.CTkFont(size=12)
        )
        self.search_entry.pack(side="left", padx=(0, 4))
        self.search_entry.bind("<Return>", lambda e: self.search_text())
        self.search_entry.bind("<Escape>", lambda e: self.clear_search())
        self.bind("<Control-f>", lambda e: self.focus_search())
        self.text_widget.bind("<Control-f>", lambda e: self.focus_search())

        ctk.CTkButton(
            search_input_frame, text="Rechercher", width=95, height=30,
            font=ctk.CTkFont(size=12), command=self.search_text
        ).pack(side="left", padx=(0, 2))

        ctk.CTkButton(
            search_input_frame, text="◀", width=32, height=30,
            font=ctk.CTkFont(size=12), command=self.search_prev
        ).pack(side="left", padx=(0, 2))

        ctk.CTkButton(
            search_input_frame, text="▶", width=32, height=30,
            font=ctk.CTkFont(size=12), command=self.search_next
        ).pack(side="left", padx=(0, 2))

        ctk.CTkButton(
            search_input_frame, text="✕", width=32, height=30,
            font=ctk.CTkFont(size=12),
            fg_color=COLORS["danger"], hover_color="#C0002E",
            command=self.clear_search
        ).pack(side="left")

        self.search_count_label = ctk.CTkLabel(
            self.search_frame,
            text="",
            font=ctk.CTkFont(size=11),
            text_color=COLORS["gray"],
            width=100
        )
        self.search_count_label.grid(row=0, column=2, padx=5, pady=10)

    def search_text(self):
        term = self.search_entry.get()
        if not term:
            return

        tw = self.text_widget._textbox  # widget tk sous-jacent
        tw.tag_remove("search_highlight", "1.0", "end")
        tw.tag_remove("search_current", "1.0", "end")
        self.search_matches = []
        self.search_index = 0

        # Configurer les tags
        tw.tag_config("search_highlight", background="#F9C80E", foreground="#000000")
        tw.tag_config("search_current", background="#FF8C00", foreground="#000000")

        start = "1.0"
        while True:
            pos = tw.search(term, start, stopindex="end", nocase=True)
            if not pos:
                break
            end_pos = f"{pos}+{len(term)}c"
            self.search_matches.append((pos, end_pos))
            tw.tag_add("search_highlight", pos, end_pos)
            start = end_pos

        count = len(self.search_matches)
        if count == 0:
            self.search_count_label.configure(text="Aucun résultat", text_color=COLORS["danger"])
        else:
            self._highlight_current()
        self.update_scrollmap()

    def _highlight_current(self):
        if not self.search_matches:
            return
        tw = self.text_widget._textbox
        tw.tag_remove("search_current", "1.0", "end")
        pos, end_pos = self.search_matches[self.search_index]
        tw.tag_add("search_current", pos, end_pos)
        tw.see(pos)
        self.search_count_label.configure(
            text=f"{self.search_index + 1}/{len(self.search_matches)}",
            text_color=COLORS["success"]
        )

    def search_next(self):
        if not self.search_matches:
            self.search_text()
            return
        self.search_index = (self.search_index + 1) % len(self.search_matches)
        self._highlight_current()
        self.update_scrollmap()

    def search_prev(self):
        if not self.search_matches:
            self.search_text()
            return
        self.search_index = (self.search_index - 1) % len(self.search_matches)
        self._highlight_current()
        self.update_scrollmap()

    def clear_search(self):
        tw = self.text_widget._textbox
        tw.tag_remove("search_highlight", "1.0", "end")
        tw.tag_remove("search_current", "1.0", "end")
        self.search_matches = []
        self.search_index = 0
        self.search_entry.delete(0, "end")
        self.search_count_label.configure(text="")
        self.update_scrollmap()

    def focus_search(self):
        self.search_entry.focus()
        self.search_entry.select_range(0, "end")
        return "break"

    def update_scrollmap(self):
        """Dessine les marqueurs de position des occurrences sur la scrollmap."""
        self.scrollmap.delete("all")
        if not self.search_matches:
            return
        self.scrollmap.update_idletasks()
        h = self.scrollmap.winfo_height()
        if h <= 1:
            return
        tw = self.text_widget._textbox
        total_lines = int(tw.index("end-1c").split(".")[0])
        if total_lines <= 0:
            return
        for i, (pos, _) in enumerate(self.search_matches):
            line = int(pos.split(".")[0])
            y = int((line / total_lines) * h)
            color = "#FF8C00" if i == self.search_index else "#F9C80E"
            self.scrollmap.create_rectangle(1, y, 9, y + 2, fill=color, outline="")

    def _scrollmap_click(self, event):
        """Clic sur la scrollmap : saute à l'occurrence la plus proche."""
        if not self.search_matches:
            return
        h = self.scrollmap.winfo_height()
        if h <= 1:
            return
        ratio = event.y / h
        tw = self.text_widget._textbox
        total_lines = int(tw.index("end-1c").split(".")[0])
        target_line = int(ratio * total_lines)
        best = min(
            range(len(self.search_matches)),
            key=lambda i: abs(int(self.search_matches[i][0].split(".")[0]) - target_line)
        )
        self.search_index = best
        self._highlight_current()
        self.update_scrollmap()

    def create_statusbar(self):
        statusbar = ctk.CTkFrame(self, height=40, corner_radius=0)
        statusbar.grid(row=3, column=0, sticky="ew", padx=0, pady=0)
        statusbar.grid_columnconfigure(0, weight=1)
        
        self.status_label = ctk.CTkLabel(
            statusbar,
            text="● Non modifié",
            text_color=COLORS["success"],
            font=ctk.CTkFont(size=11)
        )
        self.status_label.grid(row=0, column=0, padx=20, pady=10, sticky="w")
        
        stats_frame = ctk.CTkFrame(statusbar, fg_color="transparent")
        stats_frame.grid(row=0, column=1, padx=20, pady=10, sticky="e")
        
        self.stats_label = ctk.CTkLabel(
            stats_frame,
            text="Ligne 1, Colonne 1",
            font=ctk.CTkFont(size=11),
            text_color=COLORS["gray"]
        )
        self.stats_label.pack(side="right")
        
        self.text_widget.bind("<KeyRelease>", self.update_cursor_stats)
        self.text_widget.bind("<ButtonRelease>", self.update_cursor_stats)
    
    def on_text_modified(self, event=None):
        if self.text_widget.edit_modified():
            self.modified = True
            self.status_label.configure(
                text="● Modifié (non sauvegardé)",
                text_color=COLORS["warning"]
            )
            self.save_button.configure(state="normal")
            self.text_widget.edit_modified(False)
    
    def update_cursor_stats(self, event=None):
        try:
            cursor_pos = self.text_widget.index("insert")
            line, char = map(int, cursor_pos.split('.'))
            
            content = self.text_widget.get("1.0", "end-1c")
            self.line_count = content.count('\n') + 1
            self.char_count = len(content)
            self.word_count = len(content.split())
            
            stats = f"Ligne {line}/{self.line_count}, Col {char+1} | {self.char_count:,} caractères | {self.word_count:,} mots"
            self.stats_label.configure(text=stats)
        except:
            pass
    
    def save_file(self):
        if not CTkMessagebox(
            title="Confirmation",
            message="Voulez-vous sauvegarder et rechiffrer le fichier ?",
            icon="question",
            option_1="Annuler",
            option_2="Sauvegarder",
            width=500,
            height=200
        ).get() == "Sauvegarder":
            return
        
        try:
            content = self.text_widget.get("1.0", "end-1c")
            new_data = content.encode('utf-8')
            
            new_salt = SecureBuffer(os.urandom(SALT_SIZE))
            new_nonce = os.urandom(NONCE_SIZE)
            
            params = self.file_info["params"]
            new_key = derive_key(self.password, new_salt, params)
            
            new_plaintext = SecureBuffer(new_data)
            
            params_header = pack_crypto_params(
                params["MEMORY_COST"],
                params["TIME_COST"],
                params["PARALLELISM"]
            )
            associated_data = MAGIC + params_header
            
            new_ciphertext = encrypt_secure(new_plaintext, new_key, new_nonce, associated_data)
            
            with open(self.file_path, 'wb') as f:
                f.write(MAGIC)
                f.write(params_header)
                f.write(bytes(new_salt.get()))
                f.write(new_nonce)
                f.write(bytes(new_ciphertext.get()))
            
            self.modified = False
            self.status_label.configure(
                text="✓ Sauvegardé",
                text_color=COLORS["success"]
            )
            self.save_button.configure(state="disabled")
            
            secure_list = SecureList([
                new_salt, new_key, new_plaintext, new_ciphertext
            ])
            secure_list.clear()
            
            CTkMessagebox(
                title="Succès",
                message="Fichier sauvegardé et rechiffré avec succès !",
                icon="check",
                width=500,
                height=180
            )
            
        except Exception as e:
            SecureExceptionContext.clean_traceback()
            CTkMessagebox(
                title="Erreur",
                message="Échec de la sauvegarde.",
                icon="cancel",
                width=500,
                height=200
            )
    
    def center_window(self, parent):
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (1200 // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (800 // 2)
        self.geometry(f"1200x800+{x}+{y}")
    
    def on_closing(self):
        if self.modified:
            response = CTkMessagebox(
                title="Modifications non sauvegardées",
                message="Vous avez des modifications non sauvegardées.\nVoulez-vous vraiment fermer ?",
                icon="warning",
                option_1="Annuler",
                option_2="Fermer sans sauvegarder",
                option_3="Sauvegarder et fermer",
                width=550,
                height=220,
                font=ctk.CTkFont(size=13)
            ).get()
            
            if response == "Annuler":
                return
            elif response == "Sauvegarder et fermer":
                self.save_file()
        
        if hasattr(self, 'context_menu'):
            self.context_menu.destroy()
        
        self.password.clear()
        self.destroy()

# MAIN
def main():
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    app = FileListGUI()
    app.mainloop()

if __name__ == "__main__":
    main()