
import sys,hashlib , unicodedata
import aespython.key_expander, aespython.aes_cipher, aespython.cbc_mode


def simple_warn(message, *ignored):
    print >> sys.stderr, message


def decrypt_electrum_seed(enc_seed,password):


    seed_version = 11
    if True:

        b64_encrypted_data = enc_seed


        # Carefully check base64 encoding and truncate it at the first unrecoverable character group
        b64_chars_set = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')
        assert len(b64_chars_set) == 64
        for i in range(0, len(b64_encrypted_data), 4):  # iterate over 4-character long groups
            char_group_len = len(b64_encrypted_data[i:])

            if char_group_len == 1:
                #simple_warn('ignoring unrecoverable base64 suffix {!r} in encrypted seed'.format(b64_encrypted_data[i:]))
                b64_encrypted_data = b64_encrypted_data[:i]
                break

            elif 2 <= char_group_len <= 3:
                #simple_warn('adding padding to incomplete base64 suffix {!r} in encrypted seed'.format(b64_encrypted_data[i:]))
                b64_encrypted_data += '=' * (4 - char_group_len)

            for j,c in enumerate(b64_encrypted_data[i:i+4]):  # check the 4 characters in this group
                if c not in b64_chars_set:
                    if j > 1 and c == '=':   # padding characters are allowed in positions 2 and 3 of a group,
                        b64_chars_set = '='  # and once one is found all the rest must be padding
                    else:
                        #simple_warn('found invalid base64 char {!r} at position {} in encrypted seed; ignoring the rest'.format(c, i+j))
                        if j <= 1:  # character groups of length 0 or 1 are invalid: the entire group is truncated
                            b64_encrypted_data = b64_encrypted_data[:i]
                        else:       # else truncate and replace invalid characters with padding
                            b64_encrypted_data = b64_encrypted_data[:i+j]
                            b64_encrypted_data += '=' * (4-j)
                        break

        # Decode base64 and then extract the IV and encrypted_seed
        iv_and_encrypted_seed = b64_encrypted_data.decode('base64')
        if seed_version == 4 and len(iv_and_encrypted_seed) != 64:
            simple_warn('encrypted seed plus iv is {} bytes long; expected 64'.format(len(iv_and_encrypted_seed)))
        iv             = iv_and_encrypted_seed[:16]
        encrypted_seed = iv_and_encrypted_seed[16:]
        #print(iv_and_encrypted_seed)
        if len(encrypted_seed) < 16:
            #simple_warn('length of encrypted seed, {}, is less than one AES block (16), giving up'.format(len(encrypted_seed)))
            return None, None
        encrypted_seed_mod_blocksize = len(encrypted_seed) % 16

        password = password.decode()#get_password_fn()  # get a password via the callback
        #print(password)
        if password is None:
            return None, None
        if unicodedata.normalize('NFC', password) != unicodedata.normalize('NFD', password):
            if password == unicodedata.normalize('NFC', password):
                the_default = 'NFC'
            elif password == unicodedata.normalize('NFD', password):
                the_default = 'NFD'
            else:
                the_default = 'a combination'
            #simple_warn('password has different NFC and NFD encodings; only trying the default ({})'.format(the_default))
        password = password.encode('UTF-8')

        # Derive the encryption key
        key = hashlib.sha256( hashlib.sha256( password ).digest() ).digest()

        # Decrypt the seed
        key_expander  = aespython.key_expander.KeyExpander(256)
        block_cipher  = aespython.aes_cipher.AESCipher( key_expander.expand(map(ord, key)) )
        stream_cipher = aespython.cbc_mode.CBCMode(block_cipher, 16)
        stream_cipher.set_iv(bytearray(iv))
        seed = bytearray()
        for i in xrange(0, len(encrypted_seed), 16):
            seed.extend(stream_cipher.decrypt_block(map(ord, encrypted_seed[i:i+16])) )
        padding_len = seed[-1]
        # check for PKCS7 padding
        if not (1 <= padding_len <= 16 and seed.endswith(chr(padding_len) * padding_len)):
            seed = str(seed)
        else:
            seed = str(seed[:-padding_len])


    return seed



if __name__ == '__main__':
    enc_seed = "seed_base64"
    password = "user_password"

    seed = decrypt_electrum_seed(enc_seed, password)
    print(seed)