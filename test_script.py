"""CoralPay PGP Encryption SDK - entrypoint."""

import json
from lib import CoralPayPGPEncryption

def get_keys():
    """This is a test function to encrypt
    Arguments:
        data -- The plain data to be encrypted
        key_id -- The fingerprint ID for the Public PGP key to use for encryption
    """
    pgp_object = CoralPayPGPEncryption('/Users/osemeodigie/.gnupg')
    result = pgp_object.get_private_keys(None, True)

    return result # json.dumps(public_keys, indent=2)


def run_encrypt(data, key_id=None):
    """This is a test function to encrypt
    Arguments:
        data -- The plain data to be encrypted
        key_id -- The fingerprint ID for the Public PGP key to use for encryption
    """
    pgp_object = CoralPayPGPEncryption('/Users/osemeodigie/.gnupg')
    result = pgp_object.encrypt_request(data, key_id, False, True)

    return result # json.dumps(public_keys, indent=2)


def run_decrypt(data, key_id=None, passphrase=None):
    """This is a test function to decrypt
    Arguments:
        data -- The encrypted data to be decrypted
        key_id -- The fingerprint ID for the Private PGP key to use for decryption
        passphrase -- The passphrase for the Private PGP key to use for decryption
    """
    pgp_object = CoralPayPGPEncryption('/Users/osemeodigie/.gnupg')
    result = pgp_object.decrypt_response(data, key_id, passphrase)

    return result # json.dumps(public_keys, indent=2)

if __name__ == '__main__':
    # RESULT = get_keys()


    # # PUBLIC_KEY_ID = "7EA3EF3213F1648886FC41FD3F575986824BB3BA"
    # # PUBLIC_KEY_ID = "116D8CE5FDE79164D164127742B0293CB9C0069C"
    # PUBLIC_KEY_ID = "57F98902E342500F04D31EA6C69C19E7BDF8918F"
    # PLAIN_DATA = "this is a sample payload message"
    # RESULT = run_encrypt(PLAIN_DATA, PUBLIC_KEY_ID)


    PRIVATE_KEY_ID = "57F98902E342500F04D31EA6C69C19E7BDF8918F"
    PRIVATE_KEY_PASSPHRASE = "password"
    ENCRYPTED_DATA = "85010c03c69c19e7bdf8918f0107fe3d683d8d8c6e6bd6afddbafc6268b82dba04d74d5d16b139a2690811ad2c5c7ce6c902a5cd839ed47737243ed2e92f56e5203fd9ce633f123bd45dda5dadeecf4aad23b18c4841af4f03b20c070aead3be8a5bcc72cda89fcb858a23d308340721faf853565c56db04cb6f0f1e6ba32e46f83f94ad60719e21ecb1d44c4da6ec86c30634e6edafcfa2b24dc77b410825f81e535aff00ff7c70d6f354ad816270c89c8c45f4cd2fd2cea08748d0081aab107bddae665cf54571dc94a4f3c2f482301bdc9e94d068c32cea0e287f60bce746213c6053d4dbff3a00461fd5453c963f83671bb885144b4e0e85711ded3dbf901baae2c95c6022950f8ea819634ea4d24b01b39a44538c7ae8ade7a8e7ba63bb4aebb2fa45e2b9869789c14732d7c7b4387966a0d1a7109be1be6e35a38e3df3c3d02b3e365babbd0748a201f6e1ff7285e48fd8facc7a66d7878dd6"
    RESULT = run_decrypt(ENCRYPTED_DATA, PRIVATE_KEY_ID, PRIVATE_KEY_PASSPHRASE)


    # json.dumps(RESULT)
    print(RESULT) # this is the encrypted request
