import asyncio
import base64
import json
import logging
import uuid
import time
import hashlib
import os
import zlib
import shutil
import tempfile
import socket
from pathlib import Path
from typing import Dict, Any, Optional
import aiohttp
import pymax
from pymax import WebClient, Client, Message, ExtraConfig, File
from pymax.auth import ConsolePasswordProvider, PasswordProvider
from pymax.types.domain import FileAttachment
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Настройка
PHONE = "+1234567890"  # Используем произвольный, потому что для QR не нужен телефон
CHAT_ID = 0
WORK_DIR = "cache"

# Выбор версии протокола
USE_V2 = True  # True для использования версии 2 (с вложениями), False для версии 1
PROTOCOL_VERSION_1 = "IP-over-MAX-v1"
PROTOCOL_VERSION_2 = "IP-over-MAX-v2"

# Настройки TCP клиента
USE_TCP = False # True для использования TCP клиента (Client) вместо WebClient
TWO_FA_PASSWORD = None # Пароль 2FA, если нужен

# Настройки разделения вложений (из zdisk)
MAX_ATTACH_SIZE = 1024 * 1024 * 1024  # 1 GB

# Локальные порты
PTCP_PORT = 10001
PUDP_PORT = 10002
UDP_PORT = 10003
CUDP_PORT = 10005
RESPONSE_PORT = 10004
LOCAL_HOST = "127.0.0.1"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("IOTClient")
print(pymax.__version__)

# Патчим (monkeypatch) LoginResponse и AuthService в pymax, чтобы сделать поле 'token' необязательным
# и автоматически переносить текущий токен сессии, если в ответе сервера он отсутствует.
try:
    from pymax.types.domain.login import LoginResponse
    from pymax.api.auth.service import AuthService
    from pymax.types.domain.element import ElementAttributes
    from typing import Optional

    token_field = LoginResponse.model_fields.get("token")
    if token_field:
        token_field.default = None
        token_field.annotation = Optional[str]
        LoginResponse.__annotations__["token"] = Optional[str]
        LoginResponse.model_rebuild(force=True)

    url_field = ElementAttributes.model_fields.get("url")
    if url_field:
        url_field.default = None
        url_field.annotation = Optional[str]
        ElementAttributes.__annotations__["url"] = Optional[str]
        ElementAttributes.model_rebuild(force=True)

    try:
        from pymax.formatting.markdown import ElementAttributes as ElementAttributesMD
        url_field_md = ElementAttributesMD.model_fields.get("url")
        if url_field_md:
            url_field_md.default = None
            url_field_md.annotation = Optional[str]
            ElementAttributesMD.__annotations__["url"] = Optional[str]
            ElementAttributesMD.model_rebuild(force=True)
    except Exception:
        pass

    # Rebuild dependent models in bottom-up order
    from pymax.types.domain.element import Element
    from pymax.types.domain.message import Message
    from pymax.types.domain.chat import Chat
    
    Element.model_rebuild(force=True)
    Message.model_rebuild(force=True)
    Chat.model_rebuild(force=True)
    LoginResponse.model_rebuild(force=True)

    original_login = AuthService.login
    async def patched_login(self, *args, **kwargs):
        response = await original_login(self, *args, **kwargs)
        if response and response.token is None and self.app.session is not None:
            response.token = self.app.session.token
        return response
    AuthService.login = patched_login
except Exception as e:
    logger.warning(f"Не удалось применить патч к авторизации pymax: {e}")

class ZDiskCrypto:
    """Handles AES-256-GCM encryption/decryption with PBKDF2 key derivation."""
    
    ITERATIONS = 100_000
    SALT_SIZE = 16
    NONCE_SIZE = 12
    CHUNK_SIZE = 1024 * 1024 # 1MB chunks

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.backends import default_backend
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_file(self, input_path: str, output_path: str, password: str):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        salt = os.urandom(self.SALT_SIZE)
        key = self._derive_key(password, salt)
        nonce_base = os.urandom(self.NONCE_SIZE - 4)
        aesgcm = AESGCM(key)
        
        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            f_out.write(salt)
            f_out.write(nonce_base)
            chunk_index = 0
            while True:
                data = f_in.read(self.CHUNK_SIZE)
                if not data:
                    break
                nonce = nonce_base + chunk_index.to_bytes(4, 'big')
                ciphertext = aesgcm.encrypt(nonce, data, None)
                f_out.write(len(ciphertext).to_bytes(4, 'big'))
                f_out.write(ciphertext)
                chunk_index += 1

    def decrypt_file(self, input_path: str, output_path: str, password: str) -> bool:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        try:
            with open(input_path, 'rb') as f_in:
                salt = f_in.read(self.SALT_SIZE)
                nonce_base = f_in.read(self.NONCE_SIZE - 4)
                key = self._derive_key(password, salt)
                aesgcm = AESGCM(key)
                with open(output_path, 'wb') as f_out:
                    chunk_index = 0
                    while True:
                        len_bytes = f_in.read(4)
                        if not len_bytes:
                            break
                        chunk_len = int.from_bytes(len_bytes, 'big')
                        ciphertext = f_in.read(chunk_len)
                        nonce = nonce_base + chunk_index.to_bytes(4, 'big')
                        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                        f_out.write(plaintext)
                        chunk_index += 1
            return True
        except Exception as e:
            logger.error(f"Ошибка расшифровки файла: {e}")
            return False

class FileSplitter:
    """Класс для разделения файла на части со сжатием"""
    
    def __init__(self, chunk_size: int = 10 * 1024 * 1024, compress_level: int = 6):
        self.chunk_size = chunk_size
        self.compress_level = compress_level
    
    def calculate_crc32(self, file_path: str) -> str:
        crc = 0
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                crc = zlib.crc32(chunk, crc)
        return format(crc & 0xFFFFFFFF, '08x')
    
    def compress_data(self, data: bytes) -> bytes:
        return zlib.compress(data, level=self.compress_level)
    
    def split_file(self, input_file: str, output_dir: Optional[str] = None) -> Dict:
        input_path = Path(input_file)
        if not input_path.exists():
            raise FileNotFoundError(f"Файл не найден: {input_file}")
        if not input_path.is_file():
            raise IsADirectoryError(f"Путь указывает на директорию: {input_file}")
        if output_dir is None:
            output_dir = input_path.parent
        else:
            output_dir = Path(output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)

        base_name = input_path.stem
        parts_dir = output_dir / f"{base_name}_parts"
        parts_dir.mkdir(exist_ok=True)

        original_size = input_path.stat().st_size
        original_crc = self.calculate_crc32(input_file)

        parts_info = []
        part_number = 1

        compressor = zlib.compressobj(level=self.compress_level)
        compressed_size = 0
        current_part_data = bytearray()

        with open(input_file, 'rb') as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                compressed_chunk = compressor.compress(chunk)
                current_part_data.extend(compressed_chunk)
                while len(current_part_data) >= self.chunk_size:
                    to_write = current_part_data[:self.chunk_size]
                    current_part_data = current_part_data[self.chunk_size:]
                    self._write_part(parts_dir, base_name, part_number, to_write, parts_info)
                    compressed_size += len(to_write)
                    part_number += 1

            remaining = compressor.flush()
            current_part_data.extend(remaining)
            while len(current_part_data) > 0:
                to_write = current_part_data[:self.chunk_size]
                current_part_data = current_part_data[self.chunk_size:]
                self._write_part(parts_dir, base_name, part_number, to_write, parts_info)
                compressed_size += len(to_write)
                part_number += 1

        total_parts = part_number - 1
        manifest = {
            'original_file': input_path.name,
            'original_size': original_size,
            'compressed_size': compressed_size,
            'total_parts': total_parts,
            'chunk_size': self.chunk_size,
            'compress_level': self.compress_level,
            'original_crc32': original_crc,
            'parts': parts_info
        }

        manifest_path = parts_dir / f"{base_name}_manifest.json"
        with open(manifest_path, 'w', encoding='utf-8') as mf:
            json.dump(manifest, mf, indent=2, ensure_ascii=False)

        return {
            'success': True,
            'parts_dir': str(parts_dir),
            'manifest_file': str(manifest_path),
            'total_parts': total_parts,
            'original_size': original_size,
            'compressed_size': compressed_size,
            'compression_ratio': original_size / compressed_size if compressed_size > 0 else 1,
            'original_crc32': original_crc
        }

    def _write_part(self, parts_dir, base_name, part_number, data, parts_info):
        part_filename = f"{base_name}.part{part_number:04d}"
        part_path = parts_dir / part_filename
        part_crc = format(zlib.crc32(data) & 0xFFFFFFFF, '08x')
        with open(part_path, 'wb') as part_file:
            part_file.write(data)
        parts_info.append({
            'part_number': part_number,
            'filename': part_filename,
            'size': len(data),
            'crc32': part_crc
        })

class FileAssembler:
    """Класс для сборки файла из частей с распаковкой"""
    
    def __init__(self):
        pass
    
    def calculate_crc32(self, file_path: str) -> str:
        crc = 0
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                crc = zlib.crc32(chunk, crc)
        return format(crc & 0xFFFFFFFF, '08x')
    
    def decompress_data(self, data: bytes) -> bytes:
        return zlib.decompress(data)
    
    def verify_part(self, part_path: Path, expected_crc: str, expected_size: int) -> bool:
        if not part_path.exists():
            return False
        if part_path.stat().st_size != expected_size:
            return False
        with open(part_path, 'rb') as f:
            content = f.read()
            actual_crc = format(zlib.crc32(content) & 0xFFFFFFFF, '08x')
        return actual_crc == expected_crc
    
    def assemble_file(self, manifest_file: str, output_file: Optional[str] = None) -> Dict:
        manifest_path = Path(manifest_file)
        if not manifest_path.exists():
            raise FileNotFoundError(f"Манифест не найден: {manifest_file}")
        with open(manifest_path, 'r', encoding='utf-8') as mf:
            manifest = json.load(mf)

        parts_dir = manifest_path.parent
        original_filename = manifest['original_file']
        total_parts = manifest['total_parts']
        original_crc = manifest['original_crc32']
        compressed_size = manifest['compressed_size']

        if output_file is None:
            output_path = parts_dir / original_filename
        else:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

        missing_parts = []
        for part_info in manifest['parts']:
            part_path = parts_dir / part_info['filename']
            if not part_path.exists():
                missing_parts.append(part_info['part_number'])

        if missing_parts:
            raise RuntimeError(f"Отсутствуют части: {missing_parts}")

        decompressor = zlib.decompressobj()
        actual_compressed_size = 0

        try:
            with open(output_path, 'wb') as out_f:
                for part_info in manifest['parts']:
                    part_path = parts_dir / part_info['filename']
                    with open(part_path, 'rb') as p_f:
                        while True:
                            chunk = p_f.read(1024 * 1024)
                            if not chunk:
                                break
                            actual_compressed_size += len(chunk)
                            decompressed_chunk = decompressor.decompress(chunk)
                            out_f.write(decompressed_chunk)
                remaining = decompressor.flush()
                out_f.write(remaining)
        except Exception as e:
            if output_path.exists():
                output_path.unlink()
            raise RuntimeError(f"Ошибка при сборке/распаковке: {e}")

        if actual_compressed_size != compressed_size:
            if output_path.exists():
                output_path.unlink()
            raise RuntimeError(
                f"Размер собранных данных ({actual_compressed_size}) не совпадает с ожидаемым ({compressed_size})"
            )

        assembled_crc = self.calculate_crc32(str(output_path))
        if assembled_crc != original_crc:
            if output_path.exists():
                output_path.unlink()
            raise RuntimeError(
                f"Ошибка целостности! CRC32 собранного файла ({assembled_crc}) не совпадает с оригиналом ({original_crc})"
            )

        return {
            'success': True,
            'output_file': str(output_path),
            'original_crc32': original_crc,
            'original_size': manifest['original_size'],
            'compressed_size': compressed_size,
            'verified': True
        }

class ZDiskFiles:
    """Обертка для разделения и сборки файлов вложений, взятая из zdisk."""
    
    def __init__(self, temp_dir: str = None):
        if temp_dir is None:
            self.temp_dir = Path(tempfile.gettempdir()) / "ip_over_max_temp"
        else:
            self.temp_dir = Path(temp_dir)
            
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self.splitter = FileSplitter()
        self.assembler = FileAssembler()
        self._max_part_size = 10 * 1024 * 1024

    @property
    def MAX_PART_SIZE(self):
        return self._max_part_size

    @MAX_PART_SIZE.setter
    def MAX_PART_SIZE(self, value):
        self._max_part_size = value
        self.splitter.chunk_size = value

    def prepare_upload(self, file_path: str) -> dict:
        file_size = os.path.getsize(file_path)
        if file_size > self.MAX_PART_SIZE:
            result = self.splitter.split_file(file_path, output_dir=str(self.temp_dir))
            return {
                'is_split': True,
                'parts_dir': result['parts_dir'],
                'manifest_file': result['manifest_file'],
                'total_parts': result['total_parts']
            }
        else:
            return {
                'is_split': False,
                'file_path': file_path
            }

    def assemble(self, manifest_file: str, output_path: str = None) -> str:
        result = self.assembler.assemble_file(manifest_file, output_file=output_path)
        return result['output_file']

    def cleanup(self, path: str):
        try:
            p = Path(path)
            if p.is_file():
                p.unlink(missing_ok=True)
            elif p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
        except Exception:
            pass

    def clean_all(self):
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            self.temp_dir.mkdir(parents=True, exist_ok=True)

class UDPLocalProtocol(asyncio.DatagramProtocol):
    def __init__(self, callback):
        self.callback = callback

    def datagram_received(self, data, addr):
        asyncio.create_task(self.callback(data, addr))

def filter_chat(chat_id: int):
    return lambda message: message.chat_id == chat_id

class IOTClient:
    def __init__(self, phone: str, work_dir: str, use_v2: bool = USE_V2):
        self.use_v2 = use_v2
        self.protocol_name = PROTOCOL_VERSION_2 if self.use_v2 else PROTOCOL_VERSION_1
        logger.info(f"Используется протокол: {self.protocol_name} (use_v2={self.use_v2})")
        
        self._work_dir = Path(work_dir)
        self._work_dir.mkdir(parents=True, exist_ok=True)
        
        # Инициализация работы с вложениями из zdisk
        self.zdisk_files = ZDiskFiles(temp_dir=str(self._work_dir / "temp"))
        self.zdisk_files.MAX_PART_SIZE = MAX_ATTACH_SIZE
        self.zdisk_files.clean_all()
        self.zdisk_crypto = ZDiskCrypto()
        
        self._uuids_file = self._work_dir / "known_uuids.json"
        self._identity_file = self._work_dir / "identity.json"
        self._session_db = self._work_dir / "session.db"
        
        self._stop_event = asyncio.Event()

        # Проверяем, является ли это первым запуском ПРОТОКОЛА
        # Мы считаем запуск НЕ первым, если session.db существует
        if self._session_db.exists():
            self.is_first_start = False
            logger.info("Файл session.db найден, предполагаем не первый запуск.")
        else:
            self.is_first_start = True
            logger.info("Файл session.db не найден, предполагаем первый запуск.")

        # Автопроверка телефона
        dummy_phones = {"+12345678900", "+1234567890", "+00000000000", ""}
        if PHONE.strip() in dummy_phones:
            effective_use_tcp = False
            logger.info("Обнаружен фиктивный номер телефона, используется WebClient (QR).")
        else:
            effective_use_tcp = True
            logger.info("Обнаружен реальный номер телефона, используется TCP клиент.")

        if effective_use_tcp:
            class StaticPasswordProvider(PasswordProvider):
                def __init__(self, password):
                    self.password = password
                async def get_password(self, hint=None) -> str:
                    if self.password:
                        return self.password
                    provider = ConsolePasswordProvider()
                    return await provider.get_password(hint)
            
            self.client = Client(
                phone=PHONE,
                session_name="session.db",
                work_dir=work_dir,
                extra_config=ExtraConfig(reconnect=False),
                password_provider=StaticPasswordProvider(TWO_FA_PASSWORD) if TWO_FA_PASSWORD else ConsolePasswordProvider()
            )
        else:
            self.client = WebClient(
                session_name="session.db",
                work_dir=work_dir,
                extra_config=ExtraConfig(reconnect=False)
            )

        if self._load_identity():
            logger.info(f"Загружен существующий идентификатор (UUID): {self.my_uuid}")
            self.is_new_identity = False
        else:
            self.my_uuid = str(uuid.uuid4())
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.public_key = self.private_key.public_key()
            self._save_identity()
            self.is_new_identity = True
            logger.info(f"Создан новый идентификатор (UUID): {self.my_uuid}")
        
        # Загружаем сохраненные UUID
        self.known_uuids: Dict[str, str] = self._load_uuids()
        
        self.pub_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        self.my_uuid_b64 = base64.b64encode(self.my_uuid.encode()).decode()
        
        # Регистрация обработчиков
        self.client.on_message(filter_chat(CHAT_ID))(self.handle_max_message)
        self._boot_time = time.time()
        self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    @property
    def is_connected(self) -> bool:
        return hasattr(self.client, "_connection") and self.client._connection._is_open

    def _load_identity(self) -> bool:
        if self._identity_file.exists():
            try:
                with open(self._identity_file, "r") as f:
                    data = json.load(f)
                self.my_uuid = data["uuid"]
                self.private_key = serialization.load_pem_private_key(
                    data["private_key"].encode(),
                    password=None
                )
                self.public_key = self.private_key.public_key()
                return True
            except Exception as e:
                logger.error(f"Не удалось загрузить UUID/ключи: {e}")
        return False

    def _save_identity(self):
        try:
            data = {
                "uuid": self.my_uuid,
                "private_key": self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode()
            }
            with open(self._identity_file, "w") as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            logger.error(f"Не удалось сохранить UUID/ключи: {e}")

    def _load_uuids(self) -> Dict[str, str]:
        if self._uuids_file.exists():
            try:
                with open(self._uuids_file, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Не удалось загрузить известные UUID: {e}")
        return {}

    def _save_uuids(self):
        try:
            with open(self._uuids_file, "w") as f:
                json.dump(self.known_uuids, f, indent=4)
        except Exception as e:
            logger.error(f"Не удалось сохранить известные UUID: {e}")

    async def check_and_assemble(self, file_hash: str, recipient: str, file_aes_password_enc: Optional[str] = None, is_compressed: bool = False):
        temp_hash_dir = Path(self.zdisk_files.temp_dir) / f"parts_{file_hash}"
        parts_dir = temp_hash_dir / "parts"
        
        # Ищем манифест
        manifest_files = list(parts_dir.glob("*_manifest.json"))
        if not manifest_files:
            return
            
        manifest_path = manifest_files[0]
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                manifest_data = json.load(f)
        except Exception as e:
            logger.error(f"Не удалось прочитать манифест {manifest_path}: {e}")
            return
            
        # Проверяем наличие всех частей
        parts_info = manifest_data['parts']
        for part in parts_info:
            part_path = parts_dir / part['filename']
            if not part_path.exists() or part_path.stat().st_size != part['size']:
                return
                
        # Все части на месте, собираем!
        logger.info(f"Все части для хэша {file_hash} на месте. Начинаем сборку...")
        output_file = temp_hash_dir / f"payload_{file_hash}.assembled"
        
        try:
            loop = asyncio.get_running_loop()
            assembled_path = await loop.run_in_executor(
                None, 
                self.zdisk_files.assemble, 
                str(manifest_path), 
                str(output_file)
            )
            
            work_path = Path(assembled_path)
            
            # 1. Проверяем, нужно ли сначала расшифровать
            if file_aes_password_enc:
                # Это зашифрованный реальный файл или payload
                aes_password = self.decrypt_content(file_aes_password_enc)
                temp_dec_path = temp_hash_dir / f"payload_{file_hash}.dec"
                success = self.zdisk_crypto.decrypt_file(str(work_path), str(temp_dec_path), aes_password)
                if not success:
                    raise RuntimeError("Не удалось расшифровать собранный файл")
                work_path = temp_dec_path
            
            # 2. Теперь проверяем сжатие (оно всегда True для новых сообщений v2)
            if is_compressed:
                logger.info(f"Распаковка данных для хэша {file_hash}...")
                decompressed_path = temp_hash_dir / f"payload_{file_hash}.final"
                with open(work_path, 'rb') as f_in, open(decompressed_path, 'wb') as f_out:
                    decompressor = zlib.decompressobj()
                    while chunk := f_in.read(1024 * 1024):
                        f_out.write(decompressor.decompress(chunk))
                    f_out.write(decompressor.flush())
                work_path = decompressed_path

            # Попробуем определить, текст это или файл
            original_filename = manifest_data.get('original_file')
            if original_filename and not original_filename.startswith("payload_"):
                # Это реальный файл
                final_output_path = self._work_dir / original_filename
                shutil.copy2(work_path, final_output_path)
                logger.info(f"Файл получен, расшифрован и распакован: {final_output_path}")
                await self.send_to_local_port(f"Файл получен: {final_output_path}")
            else:
                # Это текстовый payload
                with open(work_path, 'rb') as res_f:
                    content = res_f.read().decode('utf-8', errors='ignore')
                
                logger.info(f"Сборка и обработка payload завершена для хэша {file_hash}. Отправляем на локальный порт.")
                await self.send_to_local_port(content)
            
            # Очищаем временную папку
            self.zdisk_files.cleanup(str(temp_hash_dir))
        except Exception as e:
            logger.error(f"Ошибка при сборке/обработке файла {file_hash}: {e}")

    async def download_file(self, url: str) -> bytes:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    return await response.read()
                raise RuntimeError(f"Не удалось скачать файл, статус: {response.status}")

    async def handle_max_message(self, msg: Message, client=None, *args, **kwargs):
        try:
            # Игнорируем старые сообщения из истории, которые приходят при старте
            msg_time = getattr(msg, 'time', 0)
            if msg_time > 10**12: # Миллисекунды -> Секунды
                msg_time /= 1000
            
            if msg_time > 0 and msg_time < self._boot_time:
                return

            data = json.loads(msg.text)
            protocol = data.get("protocol")
            msg_type = data.get("type")
            recipient = data.get("recipient")
            file_hash = data.get("file_hash")
            content = data.get("content")
            file_aes_password_enc = data.get("file_aes_password_enc")
            is_compressed = data.get("is_compressed", False)
            
            # Проверяем версию протокола
            if self.use_v2:
                if protocol not in [PROTOCOL_VERSION_1, PROTOCOL_VERSION_2]:
                    logger.warning(f"Неизвестная версия протокола: {protocol}")
                    return
            else:
                if protocol != PROTOCOL_VERSION_1:
                    logger.warning(f"Неизвестная версия протокола для v1 клиента: {protocol}")
                    return
            
            # Обработка сообщений протокола V2 с разделением через вложения
            if self.use_v2 and msg_type == "content_manifest":
                manifest_filename = data.get("manifest_filename")
                manifest_attach = None
                for attach in msg.attaches or []:
                    if isinstance(attach, FileAttachment):
                        manifest_attach = attach
                        break
                
                if manifest_attach:
                    try:
                        logger.info(f"Скачивание манифеста: {manifest_filename}")
                        file_req = await self.client.get_file_by_id(
                            msg.chat_id or CHAT_ID,
                            msg.id,
                            manifest_attach.file_id
                        )
                        if file_req and file_req.url:
                            manifest_bytes = await self.download_file(file_req.url)
                            temp_hash_dir = Path(self.zdisk_files.temp_dir) / f"parts_{file_hash}"
                            parts_dir = temp_hash_dir / "parts"
                            parts_dir.mkdir(parents=True, exist_ok=True)
                            
                            manifest_path = parts_dir / manifest_filename
                            with open(manifest_path, 'wb') as m_f:
                                m_f.write(manifest_bytes)
                                
                            logger.info(f"Манифест {manifest_filename} сохранен. Проверяем сборку...")
                            await self.check_and_assemble(file_hash, recipient, file_aes_password_enc, is_compressed)
                    except Exception as ex:
                        logger.error(f"Не удалось обработать манифест: {ex}")
                else:
                    logger.error("Манифест не найден во вложениях сообщения!")
                return
                
            elif self.use_v2 and msg_type == "content_part" and data.get("part_filename"):
                # Часть разделенного файла в V2
                part_filename = data.get("part_filename")
                part_attach = None
                for attach in msg.attaches or []:
                    if isinstance(attach, FileAttachment):
                        part_attach = attach
                        break
                        
                if part_attach:
                    try:
                        logger.info(f"Скачивание части: {part_filename}")
                        file_req = await self.client.get_file_by_id(
                            msg.chat_id or CHAT_ID,
                            msg.id,
                            part_attach.file_id
                        )
                        if file_req and file_req.url:
                            part_bytes = await self.download_file(file_req.url)
                            temp_hash_dir = Path(self.zdisk_files.temp_dir) / f"parts_{file_hash}"
                            parts_dir = temp_hash_dir / "parts"
                            parts_dir.mkdir(parents=True, exist_ok=True)
                            
                            with open(parts_dir / part_filename, 'wb') as p_f:
                                p_f.write(part_bytes)
                                
                            logger.info(f"Часть {part_filename} сохранена. Проверяем сборку...")
                            await self.check_and_assemble(file_hash, recipient, file_aes_password_enc, is_compressed)
                    except Exception as ex:
                        logger.error(f"Не удалось обработать часть вложения: {ex}")
                else:
                    logger.error("Часть вложения не найдена в сообщении!")
                return
            
            else:
                # Обычное неразделенное сообщение (с вложением или без)
                for attach in msg.attaches or []:
                    if isinstance(attach, FileAttachment):
                        try:
                            logger.info(f"Скачивание вложения файла для сообщения {msg.id}")
                            file_req = await self.client.get_file_by_id(
                                msg.chat_id or CHAT_ID,
                                msg.id,
                                attach.file_id
                            )
                            if file_req and file_req.url:
                                file_bytes = await self.download_file(file_req.url)
                                original_filename = data.get("original_filename")
                                
                                if file_aes_password_enc:
                                    # Это зашифрованные данные
                                    aes_password = self.decrypt_content(file_aes_password_enc)
                                    temp_enc_path = Path(self.zdisk_files.temp_dir) / f"temp_{file_hash}.aes"
                                    with open(temp_enc_path, 'wb') as f:
                                        f.write(file_bytes)
                                    
                                    temp_dec_path = Path(self.zdisk_files.temp_dir) / f"temp_{file_hash}.dec"
                                    success = self.zdisk_crypto.decrypt_file(str(temp_enc_path), str(temp_dec_path), aes_password)
                                    temp_enc_path.unlink(missing_ok=True)
                                    
                                    if success:
                                        with open(temp_dec_path, 'rb') as f:
                                            file_bytes = f.read()
                                        temp_dec_path.unlink(missing_ok=True)
                                    else:
                                        raise RuntimeError("Не удалось расшифровать файл")
                                
                                if is_compressed:
                                    file_bytes = zlib.decompress(file_bytes)
                                
                                if original_filename:
                                    # Это реальный файл
                                    output_path = self._work_dir / original_filename
                                    with open(output_path, 'wb') as f:
                                        f.write(file_bytes)
                                    logger.info(f"Сохранен полученный файл: {output_path}")
                                    content = f"Файл сохранен: {output_path}"
                                else:
                                    # Это текстовый payload
                                    content = file_bytes.decode('utf-8', errors='ignore')
                                    logger.info(f"Содержимое вложения успешно скачано и обработано")
                                break
                        except Exception as ex:
                            logger.error(f"Не удалось скачать/разобрать вложение: {ex}")
                
                if content is None:
                    # Если вложений не было, проверяем текстовое поле content (для V1)
                    if recipient != "broadcast":
                        content = self.decrypt_content(content)
                
                if content is None:
                    logger.warning("Контент не найден ни в тексте сообщения, ни во вложении")
                    return

                # Отправка на порт ответа
                await self.send_to_local_port(content)
                
        except Exception as e:
            logger.error(f"Ошибка при обработке сообщения: {e}")

    def decrypt_content(self, encrypted_content_b64: str) -> str:
        try:
            encrypted_content = base64.b64decode(encrypted_content_b64)
            decrypted = self.private_key.decrypt(
                encrypted_content,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Ошибка расшифровки: {e}")
            return f"[Ошибка расшифровки]"

    def encrypt_content(self, content: str, recipient_uuid_b64: str) -> str:
        pub_key_pem = self.known_uuids.get(recipient_uuid_b64)
        if not pub_key_pem:
            return content # Возможно, сначала стоит запросить повтор отправки ключей (request_repeat_start)
        
        pub_key = serialization.load_pem_public_key(pub_key_pem.encode())
        encrypted = pub_key.encrypt(
            content.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode()

    async def send_v2_large_payload(self, encrypted_payload: str, recipient: str, mode: str, file_path: Optional[str] = None, stable_id: Optional[str] = None, timestamp: Optional[int] = None) -> Optional[Message]:
        import hashlib
        import secrets
        import string
        
        temp_dir = Path(self._work_dir) / "temp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        
        file_aes_password_enc = None
        cleanup_payload = False
        
        # 1. Сначала всегда сжимаем исходные данные
        if file_path:
            raw_file_path = Path(file_path)
            compressed_file_path = temp_dir / f"{raw_file_path.name}.z"
            with open(raw_file_path, 'rb') as f_in, open(compressed_file_path, 'wb') as f_out:
                compressor = zlib.compressobj(level=6)
                while chunk := f_in.read(1024 * 1024):
                    f_out.write(compressor.compress(chunk))
                f_out.write(compressor.flush())
            payload_file_path = compressed_file_path
            cleanup_payload = True
            payload_filename = raw_file_path.name
        else:
            compressed_data = zlib.compress(encrypted_payload.encode('utf-8'))
            payload_filename = f"payload_{hashlib.sha256(compressed_data).hexdigest()}"
            payload_file_path = temp_dir / payload_filename
            with open(payload_file_path, 'wb') as tmp_f:
                tmp_f.write(compressed_data)
            cleanup_payload = True

        # 2. Теперь шифруем (уже сжатые данные)
        if recipient != "broadcast":
            # Генерируем пароль для AES
            alphabet = string.ascii_letters + string.digits
            aes_password = ''.join(secrets.choice(alphabet) for _ in range(16))
            
            # Шифруем (уже сжатый) файл
            enc_file_path = temp_dir / f"{payload_file_path.name}.aes"
            self.zdisk_crypto.encrypt_file(str(payload_file_path), str(enc_file_path), aes_password)
            
            # Шифруем пароль AES для получателя
            file_aes_password_enc = self.encrypt_content(aes_password, recipient)
            
            # Удаляем промежуточный сжатый файл, если мы создали новый зашифрованный
            if cleanup_payload:
                payload_file_path.unlink(missing_ok=True)
                
            payload_file_path = enc_file_path
            cleanup_payload = True
        
        payload_hash = self.zdisk_files.splitter.calculate_crc32(str(payload_file_path))
        
        try:
            # Подготавливаем вложение (оно может быть еще раз сжато Сплиттером, но это не страшно)
            prep = self.zdisk_files.prepare_upload(str(payload_file_path))
            
            if prep['is_split']:
                logger.info(f"Вложение превышает лимит ({self.zdisk_files.MAX_PART_SIZE} байт), разделяем на {prep['total_parts']} частей.")
                manifest_file = prep['manifest_file']
                parts_dir = Path(prep['parts_dir'])
                
                # Создаем временную директорию для маскирования имен файлов (blob_upload)
                stripped_dir = tempfile.mkdtemp(dir=str(self.zdisk_files.temp_dir))
                
                # Копируем манифест как blob_upload
                manifest_stripped = os.path.join(stripped_dir, "blob_upload")
                shutil.copy2(manifest_file, manifest_stripped)
                
                # 1. Отправляем манифест первым сообщением (с единственным вложением FILE)
                msg_payload = {
                    "protocol": self.protocol_name,
                    "type": "content_manifest",
                    "author": self.my_uuid_b64,
                    "recipient": recipient,
                    "is_split": True,
                    "is_compressed": True,
                    "file_hash": payload_hash,
                    "manifest_filename": os.path.basename(manifest_file),
                    "file_aes_password_enc": file_aes_password_enc,
                    "stable_id": stable_id,
                    "timestamp": timestamp
                }
                
                manifest_msg = await self.send_message(
                    text=json.dumps(msg_payload),
                    chat_id=CHAT_ID,
                    attachments=[File(path=manifest_stripped)]
                )
                
                # Ожидаем завершения отправки манифеста
                while not manifest_msg or not manifest_msg.id:
                    await asyncio.sleep(0.5)
                
                # Удаляем временный файл манифеста
                os.unlink(manifest_stripped)
                
                # 2. Отправляем части отдельными сообщениями (в каждом только одно вложение FILE)
                parts = sorted(list(parts_dir.glob("*.part*")))
                last_msg = None
                for i, part in enumerate(parts):
                    part_filename = part.name
                    part_payload = {
                        "protocol": self.protocol_name,
                        "type": "content_part",
                        "author": self.my_uuid_b64,
                        "recipient": recipient,
                        "is_compressed": True,
                        "file_hash": payload_hash,
                        "part_number": i + 1,
                        "part_filename": part_filename,
                        "file_aes_password_enc": file_aes_password_enc,
                        "stable_id": stable_id,
                        "timestamp": timestamp
                    }
                    
                    part_stripped = os.path.join(stripped_dir, "blob_upload")
                    shutil.copy2(str(part), part_stripped)
                    
                    part_msg = await self.send_message(
                        text=json.dumps(part_payload),
                        chat_id=CHAT_ID,
                        attachments=[File(path=part_stripped)]
                    )
                    while not part_msg or not part_msg.id:
                        await asyncio.sleep(0.5)
                        
                    os.unlink(part_stripped)
                    last_msg = part_msg
                    await asyncio.sleep(0.2)
                
                # Очищаем временную папку с частями
                shutil.rmtree(stripped_dir, ignore_errors=True)
                self.zdisk_files.cleanup(prep['parts_dir'])
                return last_msg
            else:
                # Отправка без разделения (одним файлом)
                msg_payload = {
                    "protocol": self.protocol_name,
                    "type": "content",
                    "author": self.my_uuid_b64,
                    "recipient": recipient,
                    "is_split": False,
                    "is_compressed": True,
                    "file_hash": payload_hash,
                    "original_filename": payload_filename if file_path else None,
                    "file_aes_password_enc": file_aes_password_enc,
                    "stable_id": stable_id,
                    "timestamp": timestamp
                }
                file_attach = File(path=str(payload_file_path))
                
                sent_msg = await self.send_message(
                    text=json.dumps(msg_payload),
                    chat_id=CHAT_ID,
                    attachments=[file_attach]
                )
                return sent_msg
        finally:
            if cleanup_payload:
                self.zdisk_files.cleanup(str(payload_file_path))

    async def send_message(self, chat_id: int, text: str, attachments=None) -> Optional[Message]:
        """Отправляет сообщение в обход markdown-форматтера для сохранения подчеркиваний и технических символов."""
        from pymax.protocol import Opcode
        from pymax.api.response import require_payload_model
        from pymax.types.domain import Message
        from pymax.api.messages.payloads import SendMessagePayload, SendMessagePayloadMessage
        
        attaches = []
        if attachments:
            attaches = await self.client._app.api.messages._upload_attachments(attachments)
            
        cid = self.client._app.api.messages._next_cid()
        frame = SendMessagePayload(
            chat_id=chat_id,
            message=SendMessagePayloadMessage(
                text=text,
                cid=cid,
                elements=[],
                attaches=attaches,
            ),
            notify=True
        )
        response = await self.client._app.invoke(Opcode.MSG_SEND, frame.to_payload())
        message = require_payload_model(response, Message).bind(self.client._app.api.messages)
        return message

    async def send_start_message(self):
        msg = {
            "protocol": self.protocol_name,
            "type": "start",
            "author": self.my_uuid_b64,
            "recipient": "broadcast",
            "pub_key": self.pub_key_pem
        }
        await self.send_message(text=json.dumps(msg), chat_id=CHAT_ID)

    async def request_repeat_start(self, target_uuid_b64: str):
        msg = {
            "protocol": self.protocol_name,
            "type": "repeat_start",
            "author": self.my_uuid_b64,
            "recipient": target_uuid_b64
        }
        await self.send_message(text=json.dumps(msg), chat_id=CHAT_ID)

    async def send_to_local_port(self, content: str):
        try:
            data = content.encode()
            
            # 1. Сначала пробуем TCP для надежности (особенно для больших данных)
            try:
                conn = asyncio.open_connection(LOCAL_HOST, RESPONSE_PORT)
                _, writer = await asyncio.wait_for(conn, timeout=0.1)
                writer.write(data)
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                pass

            # 2. Fallback на UDP (с обрезкой до лимита протокола)
            if len(data) > 65507:
                logger.warning(f"Входящий контент слишком велик ({len(data)} байт) для UDP. Он обрезан. Используйте TCP на порту {RESPONSE_PORT} для приема.")
                data = data[:65507]
            
            # Прямая отправка через сокет для Windows
            self._udp_socket.sendto(data, (LOCAL_HOST, RESPONSE_PORT))
        except Exception as e:
            logger.error(f"Ошибка при локальной доставке на порт {RESPONSE_PORT}: {e}")

    async def reconnect_loop(self):
        while True:
            for _ in range(3):
                try:
                    logger.info("Попытка подключения...")
                    await self.client.start()
                    # Если start() завершился без ошибок, проверяем, нужно ли остановиться
                    if self._stop_event.is_set():
                        return
                except Exception as e:
                    logger.error(f"Попытка подключения не удалась: {e}")
                
                await asyncio.sleep(2) # Короткая задержка между попытками
            
            logger.info("3 попытки не удались. Ожидание 1 минуту...")
            await asyncio.sleep(60)

    async def start(self):
        # Запуск локальных TCP слушателей для всех портов (PTCP, PUDP, UDP, CUDP)
        self.tcp_servers = []
        for port, mode in [(PTCP_PORT, "PTCP"), (PUDP_PORT, "PUDP"), (UDP_PORT, "UDP"), (CUDP_PORT, "CUDP")]:
            server = await asyncio.start_server(
                lambda r, w, m=mode: self.handle_local_tcp_request(r, w, m),
                LOCAL_HOST,
                port
            )
            self.tcp_servers.append(server)
            logger.info(f"Запущен локальный TCP сервер для {mode} на порту {port}")
        
        # Запуск цикла переподключения
        await self.reconnect_loop()

    async def handle_local_tcp_request(self, reader, writer, mode: str):
        data = await reader.read()
        writer.close()
        await writer.wait_closed()
        if data:
            await self.handle_local_request(data, None, mode)

    async def handle_local_request(self, data, addr, mode: str):
        if not data:
            return
            
        try:
            decoded = data.decode()
            if "|" in decoded:
                recipient, content = decoded.split("|", 1)
            else:
                recipient, content = "broadcast", decoded
        except Exception as e:
            logger.error(f"Не удалось разобрать локальный запрос: {e}")
            return
        
        file_path = None
        if content.startswith("FILE:"):
            parts = content[5:].split("|", 1)
            file_path = parts[0]
            content = parts[1] if len(parts) > 1 else ""

        timestamp = int(time.time() * 1000)

        if mode == "UDP":
            # UDP: отправка даже без проверки подключения
            asyncio.create_task(self.send_max_message(content, recipient, "UDP", file_path, timestamp))
        elif mode == "CUDP":
            # CUDP: аналогично UDP, но с удалением через минуту
            asyncio.create_task(self.send_max_cudp(content, recipient, file_path, timestamp))
        elif mode == "PUDP":
            # PUDP: ожидание подключения
            while not self.is_connected:
                await asyncio.sleep(1)
            await self.send_max_message(content, recipient, "PUDP", file_path, timestamp)
        elif mode == "PTCP":
            # PTCP: проверка истории
            await self.send_max_ptcp(content, recipient, file_path, timestamp)

    async def send_max_cudp(self, content: str, recipient: str, file_path: Optional[str] = None, timestamp: Optional[int] = None):
        encrypted = self.encrypt_content(content, recipient) if content else ""
        message_ids = []
        
        # Если включена v2 и (зашифрованный payload большой ИЛИ есть файл), отправляем как тех.информацию + вложение (с разделением)
        if self.use_v2 and (len(encrypted) > 3000 or file_path):
            try:
                sent_msg = await self.send_v2_large_payload(encrypted, recipient, "CUDP", file_path, timestamp=timestamp)
                if sent_msg:
                    message_ids.append(sent_msg.id)
            except Exception as e:
                logger.error(f"Не удалось отправить CUDP сообщение V2 с разделением: {e}")
        else:
            # Дробление/V1/маленькое сообщение V2
            chunk_size = 3000
            parts = [encrypted[i:i+chunk_size] for i in range(0, len(encrypted), chunk_size)] if encrypted else [""]
            
            for i, part in enumerate(parts):
                msg = {
                    "protocol": self.protocol_name,
                    "type": "content" if len(parts) == 1 else "content_part",
                    "author": self.my_uuid_b64,
                    "recipient": recipient,
                    "content": part,
                    "part": i + 1,
                    "total_parts": len(parts),
                    "timestamp": timestamp
                }
                try:
                    sent_msg = await self.send_message(text=json.dumps(msg), chat_id=CHAT_ID)
                    if sent_msg:
                        message_ids.append(sent_msg.id)
                except Exception as e:
                    logger.error(f"Не удалось отправить CUDP сообщение: {e}")

        if message_ids:
            logger.info(f"CUDP: Отправлено сообщений: {len(message_ids)}, удаление через 60 сек.")
            await asyncio.sleep(60)
            try:
                await self.client.delete_message(chat_id=CHAT_ID, message_ids=message_ids, for_me=False)
                logger.info(f"CUDP: Удалены сообщения {message_ids}")
            except Exception as e:
                logger.error(f"Не удалось удалить CUDP сообщения {message_ids}: {e}")

    async def send_max_message(self, content: str, recipient: str, mode: str, file_path: Optional[str] = None, timestamp: Optional[int] = None):
        encrypted = self.encrypt_content(content, recipient) if content else ""
        
        # Если включена v2 и (зашифрованный payload большой ИЛИ есть файл), отправляем как тех.информацию + вложение (с разделением)
        if self.use_v2 and (len(encrypted) > 3000 or file_path):
            try:
                await self.send_v2_large_payload(encrypted, recipient, mode, file_path, timestamp=timestamp)
            except Exception as e:
                logger.error(f"Не удалось отправить сообщение {mode} V2 с разделением: {e}")
        else:
            # Дробление/V1/маленькое сообщение V2
            chunk_size = 3000
            parts = [encrypted[i:i+chunk_size] for i in range(0, len(encrypted), chunk_size)] if encrypted else [""]
            
            for i, part in enumerate(parts):
                msg = {
                    "protocol": self.protocol_name,
                    "type": "content" if len(parts) == 1 else "content_part",
                    "author": self.my_uuid_b64,
                    "recipient": recipient,
                    "content": part,
                    "part": i + 1,
                    "total_parts": len(parts),
                    "timestamp": timestamp
                }
                try:
                    await self.send_message(text=json.dumps(msg), chat_id=CHAT_ID)
                except Exception as e:
                    logger.error(f"Не удалось отправить сообщение {mode} (подключение={self.is_connected}): {e}")

    async def send_max_ptcp(self, content: str, recipient: str, file_path: Optional[str] = None, timestamp: Optional[int] = None):
        encrypted = self.encrypt_content(content, recipient) if content else ""
        
        # Если включена v2 и (зашифрованный payload большой ИЛИ есть файл), отправляем через систему вложений
        if self.use_v2 and (len(encrypted) > 3000 or file_path):
            import hashlib
            
            # Уникальный стабильный ID для этого конкретного запроса на отправку.
            # Включаем timestamp, чтобы повторная отправка того же контента считалась новым сообщением.
            stable_base = f"{content}:{timestamp}:{file_path}"
            stable_id = hashlib.sha256(stable_base.encode()).hexdigest()

            while True:
                try:
                    if self.is_connected:
                        history = await self.client.fetch_history(CHAT_ID, backward=50)
                        found = False
                        if history:
                            for m in history:
                                try:
                                    m_data = json.loads(m.text)
                                    if m_data.get("stable_id") == stable_id and m_data.get("author") == self.my_uuid_b64:
                                        found = True
                                        break
                                except:
                                    continue
                        
                        if found:
                            logger.info("PTCP: Сообщение найдено в истории, доставка подтверждена.")
                            break
                        
                        logger.info("PTCP: Сообщение не найдено, отправка...")
                        await self.send_v2_large_payload(encrypted, recipient, "PTCP", file_path, stable_id=stable_id, timestamp=timestamp)
                except Exception as e:
                    logger.error(f"Ошибка проверки/отправки PTCP: {e}")
                
                await asyncio.sleep(15)
        else:
            # Логика для V1 или маленьких сообщений
            msg_payload = {
                "protocol": self.protocol_name,
                "type": "content",
                "author": self.my_uuid_b64,
                "recipient": recipient,
                "content": encrypted,
                "timestamp": timestamp
            }
            payload_str = json.dumps(msg_payload)
            
            while True:
                try:
                    if self.is_connected:
                        history = await self.client.fetch_history(CHAT_ID, backward=50)
                        found = False
                        if history:
                            for m in history:
                                if m.text == payload_str:
                                    found = True
                                    break
                        
                        if found:
                            logger.info("PTCP: Сообщение найдено в истории, доставка подтверждена.")
                            break
                        
                        logger.info("PTCP: Сообщение не найдено, отправка/повторная отправка...")
                        await self.send_message(text=payload_str, chat_id=CHAT_ID)
                except Exception as e:
                    logger.error(f"Ошибка проверки/отправки PTCP: {e}")
                
                await asyncio.sleep(15)

async def main():
    # Настройка - обычно считывается из файла конфигурации или переменных окружения
    phone = "+1234567890" 
    work_dir = "cache"
    
    # Передаем USE_V2 из глобальной конфигурации
    iot = IOTClient(phone, work_dir, use_v2=USE_V2)
    
    @iot.client.on_start()
    async def on_start(*args, **kwargs):
        if iot.is_first_start or iot.is_new_identity:
            logger.info("Первый запуск сессии или новый UUID, отправка UUID и публичного ключа.")
            await iot.send_start_message()
            iot.is_first_start = False
            iot.is_new_identity = False
            
    await iot.start()

if __name__ == "__main__":
    asyncio.run(main())
