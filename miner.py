import confirmer
from signature_manager import SignatureManager

confirmer = confirmer.TokenVerifier()
signature_manager = SignatureManager()

private_key, public_key = signature_manager.generate_keypair()
print(private_key, public_key)
coins = 0

mine = True
i = 0

while mine:
    nonce = str(i).encode()
    validation_result = confirmer.validate_token(nonce, public_key)

    if validation_result:
        coins += 1
        print(f'i: {i} | NONCE {nonce} VALIDATED | coinnumber: {coins}')
    if i % 1_000_000 == 0:
        print(f'Million {i // 1_000_000}')

    i += 1
#token_hex = '0000021092e4ebeaa2ef8b1ce9b099ff6cb86549c55647a57ada51b21aadbf17'
#transfer_number = 0
#owner_public_key = 'b2b17ca818e27bbbfb7365731d2de0cdbed110d12ac2a31ab410f8daa280c7e4'
#receiver_public_key = 'fc9ec2aaf5a13166f79001a9f8122c02c0b266eb9fd8ec2a417e8b04eb8db23e'

#transaction_message = f"{token_hex}:{transfer_number}:{owner_public_key}->{receiver_public_key}".encode()
#signature = signature_manager.sign(private_key, transaction_message)
#print(confirmer.transfer_token(
#    token=bytes.fromhex(token_hex),
#    signature=signature,
#    receiver_public_key=receiver_public_key
#))
