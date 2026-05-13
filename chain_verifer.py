import hashlib
import json
from signature_manager import SignatureManager

class ChainVerifier:
    def __init__(self, chain_file_name='chain.txt'):
        self.chain_file_name = chain_file_name
        self.TARGET = 2**219
        self.signature_manager = SignatureManager()

    def check_chain(self):
        with open(self.chain_file_name, mode='r') as file:
            blocks = [json.loads(line) for line in file.readlines()]
        if not blocks:
            print('Пустая цепочка')
            return True
        prev_block_hash = self.__get_double_hash(b'aboba')
        tokens_state = {}

        for i, block in enumerate(blocks):
            block_hash = self.__get_double_hash(json.dumps(block).encode())
            if block.get('prev_block_hash') != prev_block_hash.hex():
                print(f'❌ РАЗРЫВ ЦЕПОЧКИ В БЛОКЕ №{i}: неверный prev_block_hash')
                return False
            if not self.__check_block(block, tokens_state):
                print(f'❌ ОШИБКА В БЛОКЕ №{i}')
                return False

            prev_block_hash = block_hash

        print('✅ Цепь валидна')
        return True

    def __check_block(self, block: dict, tokens_state: dict):
        token_hex = block['token']

        if block['type'] == 'mint':
            return self.__check_mint_block(block, tokens_state)
        elif block['type'] == 'transfer':
            return self.__check_transfer_block(block, tokens_state)
        return False

    def __check_mint_block(self, block: dict, tokens_state: dict):
        token_hex = block['token']

        if token_hex in tokens_state:
            print(f'   ❌ Токен {token_hex[:8]}... уже существует')
            return False

        token_bytes = bytes.fromhex(token_hex)
        creator_public_key_bytes = block['creator_public_key'].encode()
        nonce_bytes = block['nonce'].encode()
        prev_block_hash = bytes.fromhex(block['prev_block_hash'])

        expected_token = self.__get_double_hash(
            prev_block_hash + creator_public_key_bytes + nonce_bytes
        )

        if token_bytes != expected_token:
            print(f'   ❌ Неверный хеш токена')
            return False

        token_int = int.from_bytes(token_bytes, 'big')
        if token_int > self.TARGET:
            print(f'   ❌ Токен не соответствует сложности')
            return False

        tokens_state[token_hex] = block['creator_public_key']
        return True

    def __check_transfer_block(self, block: dict, tokens_state: dict):
        token_hex = block['token']

        if token_hex not in tokens_state:
            print(f'   ❌ Токен {token_hex[:8]}... не существует')
            return False

        expected_owner = tokens_state[token_hex]
        if block['sender_public_key'] != expected_owner:
            print(f'   ❌ Отправитель не является владельцем')
            return False
        message = block['transaction_message'].encode()
        signature = bytes.fromhex(block['signature'])
        if not self.signature_manager.verify(expected_owner, message, signature):
            print(f'   ❌ Неверная подпись')
            return False
        expected_message = f"{token_hex}:{block['transfer_number']}:{expected_owner}->{block['owner_public_key']}"
        if block['transaction_message'] != expected_message:
            print(f'   ❌ Неверное сообщение транзакции')
            return False
        tokens_state[token_hex] = block['owner_public_key']
        return True

    def __get_double_hash(self, data: bytes) -> bytes:
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

ver = ChainVerifier()
print(ver.check_chain())
