import asyncio
import base64
import json
import logging
import uuid
import time
from pathlib import Path
from typing import Dict, Any, Optional

from pymax import MaxClient, Message
from pymax.filters import Filters
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Configuration
PHONE = "+1234567890"  # Should be provided or taken from env
CHAT_ID = 0
WORK_DIR = "cache"
PROTOCOL_NAME = "IP-over-MAX-v1"

# Local Ports
PTCP_PORT = 10001
PUDP_PORT = 10002
UDP_PORT = 10003
CUDP_PORT = 10005
RESPONSE_PORT = 10004
LOCAL_HOST = "127.0.0.1"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("IOTClient")

class UDPLocalProtocol(asyncio.DatagramProtocol):
    def __init__(self, callback):
        self.callback = callback

    def datagram_received(self, data, addr):
        asyncio.create_task(self.callback(data, addr))

class IOTClient:
    def __init__(self, phone: str, work_dir: str):
        self._work_dir = Path(work_dir)
        self._work_dir.mkdir(parents=True, exist_ok=True)
        self._uuids_file = self._work_dir / "known_uuids.json"
        self._identity_file = self._work_dir / "identity.json"
        self._session_db = self._work_dir / "session.db"
        
        # Check if this is the first start of the PROTOCOL
        # We consider it NOT the first start if session.db exists
        # Important: check this BEFORE initializing MaxClient because it touches the file
        if self._session_db.exists():
            self.is_first_start = False
            logger.info("session.db found, assuming not first start.")
        else:
            self.is_first_start = True
            logger.info("session.db not found, assuming first start.")

        self.client = MaxClient(
            phone=phone,
            work_dir=work_dir,
            reconnect=False # We handle reconnect ourselves
        )

        if self._load_identity():
            logger.info(f"Loaded existing identity: {self.my_uuid}")
            self.is_new_identity = False
        else:
            self.my_uuid = str(uuid.uuid4())
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.public_key = self.private_key.public_key()
            self._save_identity()
            self.is_new_identity = True
            logger.info(f"Generated new identity: {self.my_uuid}")
        
        # Загружаем сохраненные UUID
        self.known_uuids: Dict[str, str] = self._load_uuids()
        
        self.pub_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        self.my_uuid_b64 = base64.b64encode(self.my_uuid.encode()).decode()
        
        # Register handlers
        self.client.on_message(Filters.chat(CHAT_ID))(self.handle_max_message)

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
                logger.error(f"Failed to load identity: {e}")
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
            logger.error(f"Failed to save identity: {e}")

    def _load_uuids(self) -> Dict[str, str]:
        if self._uuids_file.exists():
            try:
                with open(self._uuids_file, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load known_uuids: {e}")
        return {}

    def _save_uuids(self):
        try:
            with open(self._uuids_file, "w") as f:
                json.dump(self.known_uuids, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to save known_uuids: {e}")

    async def handle_max_message(self, msg: Message):
        try:
            data = json.loads(msg.text)
            if data.get("protocol") != PROTOCOL_NAME:
                return
            
            msg_type = data.get("type")
            author = data.get("author")
            recipient = data.get("recipient")
            
            if msg_type == "start":
                new_key = data.get("pub_key")
                if self.known_uuids.get(author) != new_key:
                    self.known_uuids[author] = new_key
                    self._save_uuids()
                    logger.info(f"Learned and saved new UUID: {author}")
            elif msg_type == "repeat_start":
                if recipient == self.my_uuid_b64 or recipient == "broadcast":
                    await self.send_start_message()
            elif author not in self.known_uuids and author != self.my_uuid_b64:
                await self.request_repeat_start(author)
                return

            # Handle content
            if msg_type in ["content", "content_part"]:
                if recipient == "broadcast" or recipient == self.my_uuid_b64:
                    content = data.get("content")
                    if recipient != "broadcast":
                        content = self.decrypt_content(content)
                    
                    # Send to response port
                    await self.send_to_local_port(content)
                    
        except Exception as e:
            logger.error(f"Error handling message: {e}")

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
            logger.error(f"Decryption failed: {e}")
            return f"[Decryption Failed]"

    def encrypt_content(self, content: str, recipient_uuid_b64: str) -> str:
        if recipient_uuid_b64 == "broadcast":
            return content
        
        pub_key_pem = self.known_uuids.get(recipient_uuid_b64)
        if not pub_key_pem:
            return content # Should probably request_repeat_start first
        
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

    async def send_start_message(self):
        msg = {
            "protocol": PROTOCOL_NAME,
            "type": "start",
            "author": self.my_uuid_b64,
            "recipient": "broadcast",
            "pub_key": self.pub_key_pem
        }
        await self.client.send_message(text=json.dumps(msg), chat_id=CHAT_ID)

    async def request_repeat_start(self, target_uuid_b64: str):
        msg = {
            "protocol": PROTOCOL_NAME,
            "type": "repeat_start",
            "author": self.my_uuid_b64,
            "recipient": target_uuid_b64
        }
        await self.client.send_message(text=json.dumps(msg), chat_id=CHAT_ID)

    async def send_to_local_port(self, content: str):
        try:
            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(
                lambda: asyncio.DatagramProtocol(),
                remote_addr=(LOCAL_HOST, RESPONSE_PORT)
            )
            transport.sendto(content.encode())
            transport.close()
        except Exception as e:
            logger.error(f"Failed to send to response port: {e}")

    async def reconnect_loop(self):
        while True:
            for _ in range(3):
                try:
                    logger.info("Attempting to connect...")
                    await self.client.start()
                    # If start() returns cleanly, check if we should stop
                    if self.client._stop_event.is_set():
                        return
                except Exception as e:
                    logger.error(f"Connection attempt failed: {e}")
                
                await asyncio.sleep(2) # Short delay between attempts
            
            logger.info("3 attempts failed. Waiting 1 minute...")
            await asyncio.sleep(60)

    async def start(self):
        loop = asyncio.get_running_loop()
        
        # Start local listeners
        await loop.create_datagram_endpoint(
            lambda: UDPLocalProtocol(lambda d, a: self.handle_local_request(d, a, "PTCP")),
            local_addr=(LOCAL_HOST, PTCP_PORT)
        )
        await loop.create_datagram_endpoint(
            lambda: UDPLocalProtocol(lambda d, a: self.handle_local_request(d, a, "PUDP")),
            local_addr=(LOCAL_HOST, PUDP_PORT)
        )
        await loop.create_datagram_endpoint(
            lambda: UDPLocalProtocol(lambda d, a: self.handle_local_request(d, a, "UDP")),
            local_addr=(LOCAL_HOST, UDP_PORT)
        )
        await loop.create_datagram_endpoint(
            lambda: UDPLocalProtocol(lambda d, a: self.handle_local_request(d, a, "CUDP")),
            local_addr=(LOCAL_HOST, CUDP_PORT)
        )
        
        # Start reconnect loop
        await self.reconnect_loop()

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
            logger.error(f"Failed to parse local request: {e}")
            return
        
        if mode == "UDP":
            # UDP: send even without checking connection
            asyncio.create_task(self.send_max_message(content, recipient, "UDP"))
        elif mode == "CUDP":
            # CUDP: like UDP but delete after a minute
            asyncio.create_task(self.send_max_cudp(content, recipient))
        elif mode == "PUDP":
            # PUDP: wait for connection
            while not self.client.is_connected:
                await asyncio.sleep(1)
            await self.send_max_message(content, recipient, "PUDP")
        elif mode == "PTCP":
            # PTCP: check history
            await self.send_max_ptcp(content, recipient)

    async def send_max_cudp(self, content: str, recipient: str):
        encrypted = self.encrypt_content(content, recipient)
        
        # Max message length is 4000. JSON + base64 overhead...
        # Let's split into 3000 char chunks to be safe.
        chunk_size = 3000
        parts = [encrypted[i:i+chunk_size] for i in range(0, len(encrypted), chunk_size)]
        
        message_ids = []
        for i, part in enumerate(parts):
            msg = {
                "protocol": PROTOCOL_NAME,
                "type": "content" if len(parts) == 1 else "content_part",
                "author": self.my_uuid_b64,
                "recipient": recipient,
                "content": part,
                "part": i + 1,
                "total_parts": len(parts)
            }
            try:
                sent_msg = await self.client.send_message(text=json.dumps(msg), chat_id=CHAT_ID)
                if sent_msg:
                    message_ids.append(sent_msg.id)
            except Exception as e:
                logger.error(f"Failed to send CUDP message: {e}")

        if message_ids:
            logger.info(f"CUDP: Sent {len(message_ids)} messages, will delete in 60s.")
            await asyncio.sleep(60)
            try:
                await self.client.delete_message(chat_id=CHAT_ID, message_ids=message_ids, for_me=False)
                logger.info(f"CUDP: Deleted messages {message_ids}")
            except Exception as e:
                logger.error(f"Failed to delete CUDP messages {message_ids}: {e}")

    async def send_max_message(self, content: str, recipient: str, mode: str):
        encrypted = self.encrypt_content(content, recipient)
        
        # Max message length is 4000. JSON + base64 overhead...
        # Let's split into 3000 char chunks to be safe.
        chunk_size = 3000
        parts = [encrypted[i:i+chunk_size] for i in range(0, len(encrypted), chunk_size)]
        
        for i, part in enumerate(parts):
            msg = {
                "protocol": PROTOCOL_NAME,
                "type": "content" if len(parts) == 1 else "content_part",
                "author": self.my_uuid_b64,
                "recipient": recipient,
                "content": part,
                "part": i + 1,
                "total_parts": len(parts)
            }
            try:
                await self.client.send_message(text=json.dumps(msg), chat_id=CHAT_ID)
            except Exception as e:
                logger.error(f"Failed to send {mode} message (is_connected={self.client.is_connected}): {e}")

    async def send_max_ptcp(self, content: str, recipient: str):
        encrypted = self.encrypt_content(content, recipient)
        msg_payload = {
            "protocol": PROTOCOL_NAME,
            "type": "content",
            "author": self.my_uuid_b64,
            "recipient": recipient,
            "content": encrypted
        }
        payload_str = json.dumps(msg_payload)
        
        while True:
            # Check history
            try:
                if self.client.is_connected:
                    history = await self.client.fetch_history(CHAT_ID, backward=50)
                    found = False
                    if history:
                        for m in history:
                            if m.text == payload_str:
                                found = True
                                break
                    
                    if found:
                        logger.info("PTCP: Message found in history, delivery confirmed.")
                        break
                    
                    logger.info("PTCP: Message not found, sending/resending...")
                    await self.client.send_message(text=payload_str, chat_id=CHAT_ID)
            except Exception as e:
                logger.error(f"PTCP send/check error: {e}")
            
            await asyncio.sleep(15) # Wait before re-checking/resending

async def main():
    # Configuration - typically these would come from a config file or env vars
    phone = "+1234567890" 
    work_dir = "cache"
    
    iot = IOTClient(phone, work_dir)
    
    @iot.client.on_start
    async def on_start():
        if iot.is_first_start or iot.is_new_identity:
            logger.info("First session start or new identity, sending UUID and Public Key.")
            await iot.send_start_message()
            iot.is_first_start = False
            iot.is_new_identity = False
            
    await iot.start()

if __name__ == "__main__":
    asyncio.run(main())
