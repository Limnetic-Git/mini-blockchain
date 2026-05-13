import hashlib, json, time
from signature_manager import SignatureManager

class TokenVerifier:
    def __init__(self):
        try:
            with open('chain.txt', 'r') as file:
                last_block_bytes = file.readlines()[-1].strip().encode()
                self.prev_block_hash = self.__get_double_hash(last_block_bytes)
        except (FileNotFoundError, json.JSONDecodeError):
            print('☢️ ФАЙЛ С ИСТОРИЕЙ НЕ НАЙДЕН! ИСТОРИЯ ОБНУЛЕНА ☢️')
            self.prev_block_hash = self.__get_double_hash(b'aboba')
        self.TARGET = 2**219
        self.signature_manager = SignatureManager()

    def validate_token(self, nonce: bytes, creator_public_key: str):
        try:
            nonce.decode()
        except UnicodeDecodeError:
            print('unicode decode error')
            return False

        token = self.__get_double_hash(self.prev_block_hash + creator_public_key.encode() + nonce)
        token_int = int.from_bytes(token, 'big')

        if token_int <= self.TARGET:
            self.__mint_token(token, nonce, creator_public_key)
            return True
        return False

    def __mint_token(self, token: bytes, nonce: bytes, creator_public_key: str):
        block = {
            'type': 'mint',
            'token': token.hex(),
            'prev_block_hash': self.prev_block_hash.hex(),
            'nonce': nonce.decode(),
            'creator_public_key': creator_public_key,
            'timestamp': time.time(),
        }
        with open('chain.txt', mode='a') as file:
            file.write(json.dumps(block) + '\n')

        block_bytes = json.dumps(block).encode()
        self.prev_block_hash = self.__get_double_hash(block_bytes)

    def transfer_token(self, token: bytes, signature: bytes, receiver_public_key: str):
        token_data = self.__get_block_data(token)
        if not token_data: return False
        owner_public_key = token_data['creator_public_key' if token_data['type'] == 'mint' else 'owner_public_key']
        transfer_number = 0 if token_data['type'] == 'mint' else token_data['transfer_number']+1
        transaction_message = f"{token.hex()}:{transfer_number}:{owner_public_key}->{receiver_public_key}".encode()
        if self.signature_manager.verify(owner_public_key, transaction_message, signature):
            block = {
                'type': 'transfer',
                'token': token_data['token'],
                'prev_block_hash': self.prev_block_hash.hex(),
                'sender_public_key': owner_public_key,
                'owner_public_key': receiver_public_key,
                'creator_public_key': token_data['creator_public_key'],
                'transaction_message': transaction_message.decode(),
                'signature': signature.hex(),
                'transfer_number': transfer_number,
                'timestamp': time.time(),
            }
            with open('chain.txt', mode='a') as file:
                file.write(json.dumps(block) + '\n')
            block_bytes = json.dumps(block).encode()
            self.prev_block_hash = self.__get_double_hash(block_bytes)
            return True
        return False

    def __get_block_data(self, token: bytes):
        token_hex = token.hex()
        with open('chain.txt', mode='r') as file:
            blocks = [json.loads(line) for line in file.readlines()]
            for i in range(len(blocks)-1, -1, -1):
                block = blocks[i]
                if block['token'] == token_hex:
                    return block

    def __get_double_hash(self, data: bytes) -> bytes:
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()
