# pylint: disable=no-member,import-error
"""CoralPayPGPEncryption Class
"""

import logging
from sys import stdout
import time
import datetime
import json
import binascii
import codecs
import gnupg
import array

class CoralPayPGPEncryption:
    """CoralPayPGPEncryption Class"""

    logger = None # the logger instance to use

    def __init__(self, homedir='/path/to/home/directory'):
        self.gpg = gnupg.GPG(gnupghome=homedir) # gnupg.GPG(gnupghome='/path/to/home/directory')
        self.gpg.encoding = 'utf-8' # set default the character encoding standard
        self.logger = logging.getLogger("CoralPayLogger") # name of the logger
        # configure logger
        self.logger.setLevel(logging.DEBUG)
        log_formatter = logging.Formatter\
        ("%(name)-12s %(asctime)s %(levelname)-8s %(filename)s:%(funcName)s %(message)s")
        console_handler = logging.StreamHandler(stdout)
        console_handler.setFormatter(log_formatter)
        self.logger.addHandler(console_handler)
        self.service = None


    def get_public_keys(self, key_fingerprint=None, prettify=True):
        """This returns a list of all the public keys within the GPG keyChain on the machine

        Keyword Arguments:
            key_fingerprint {str} -- if set, the public key with this fingerprint will be returned
            prettify {bool} -- should prettify result ? (default: {True})

        Returns:
            dict/str -- the list of all public keys within the GPG keychain
        """
        public_keys = dict() # default value is an empty dictionary

        if key_fingerprint is not None:
            public_keys = self.gpg.search_keys(key_fingerprint)
        else:
            public_keys = self.gpg.list_keys() # same as gpg.list_keys(False)

        return json.dumps(public_keys, indent=2) if prettify else json.dumps(public_keys)


    def get_private_keys(self, key_fingerprint=None, prettify=True):
        """This returns a list of all the private keys within the GPG keyChain on the machine

        Keyword Arguments:
            key_fingerprint {str} -- if set, the public key with this fingerprint will be returned
            prettify {bool} -- should prettify result ? (default: {True})

        Returns:
            dict/str -- the list of all private keys within the GPG keychain
        """
        private_keys = dict() # default value is an empty dictionary

        if key_fingerprint is not None:
            private_keys = self.gpg.search_keys(key_fingerprint)
        else:
            private_keys = self.gpg.list_keys(True)

        return json.dumps(private_keys, indent=2) if prettify else json.dumps(private_keys)


    def encrypt_request(self, request, key_fingerprint=None, armor=True, should_hex=True):
        """This encrypts the passed in request data with the key_fingerprint of the public key
        within the GPG keyChain and return an Armor / Hex output based on the last
        flag passed into this method.

        Keyword Arguments:
            request {str} -- the request to Cgate that will be encrypted
            key_fingerprint {str} -- the fingerprint of the public key to use for encrypting
            armor {bool} -- should return armored or binary result ? (default: {True for amor})
            should_hex {bool} -- should return as hex or binary result ? (default: {True for hex})

        Returns:
            str -- the encrypted request
        """
        # set the character encoding to something that supports binary
        if armor is False:
            self.gpg.encoding = 'latin-1'

        result = self.gpg.encrypt(
            data=request,
            recipients=key_fingerprint,
            always_trust=True,
            armor=armor
        )

        if result is None: # log error here
            return 'No output from Encryption function!'

        if result.ok is False: # log error here
            self.logger.error(
                'An Error Occurred while Encrypting! \nStatus: %s \n Error: %s',
                result.status,
                result.stderr
            )
            return 'Status: {stat} || Error: {err}'.format(stat=result.status, err=result.stderr)

        encrypted_message = str(result)
        # reset the character encoding back to the default utf-8
        if armor is False:
            self.gpg.encoding = 'utf-8'

        if not armor and should_hex: # convert to hex here
            return encrypted_message.encode("latin-1").hex() # pylint: disable=no-member

        return encrypted_message


    def decrypt_response(self, response, key_fingerprint=None, passphrase=None):
        """This decrypts the passed in response data with the key_fingerprint and passphrase
        of the private key within the GPG keyChain and return an Armor / Hex output
        based on the last flag passed into this method.

        Keyword Arguments:
            response {str} -- the response from Cgate that will be decrypted
            key_fingerprint {str} -- the fingerprint of the private key to use for decrypting
            passphrase {str} -- the passphrase of the private key to use for decrypting

        Returns:
            str -- the decrypted message
        """
        # convert from hex to binary here
        binary_response = binascii.unhexlify(response)

        result = self.gpg.decrypt(
            message=binary_response,
            # recipients=key_fingerprint,
            passphrase=passphrase,
            extra_args=['--ignore-mdc-error'], # ignore the MDC error
            always_trust=True
        )

        if result is None: # log error here
            return 'No output from Decryption function!'

        if result.ok is False: # log error here
            self.logger.error(
                'An Error Occurred while Decrypting! \nStatus: %s \n Error: %s',
                result.status,
                result.stderr
            )
            return 'Status: {stat} || Error: {err}'.format(stat=result.status, err=result.stderr)

        return str(result)
