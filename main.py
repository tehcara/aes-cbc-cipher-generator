#!/usr/bin/env python3

'''
Course: TZVM163 Cisco Python programming (OpenEDG)
Student Name: Caroline Lau Campbell
PI: F859249X

Assignment: Create a simple cipher generator - when a word is entered, it will
convert it to ciphertext based on a given 'key' based on your birth month (01 
to 12).

DISCLAIMER: This project is for educational purposes only. Plain text 
documents should not be used to store sensitive data IRL. Nor should secure 
keys, etc, be displayed IRL.
'''

### Import statements ###
from secrets import token_bytes
from time import sleep
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
'''
CBC (Ciphertext Block Chaining) is a classic mode of AES operation. It 
encrypts data but does not authenticate it. PKCS7 padding adds 1-byte or more 
to ensure the plaintext is padded to 16-byte blocks. PBKDF2 is a popular KDF 
(Key Derivation Function). Derived key length is set to 32-bytes for 
compliance with AES-256. Minimum recommended iterations for hashing is 1 
million. SHA512 is used with the KDF (PBKDF2) as the hash algorithm.

Ref: https://pycryptodome.readthedocs.io/en/latest/
'''

### Custom exception classes ###
class EmptyStringError(Exception): # catch empty str errors
    pass
class OneCharBirthMonthError(Exception): # catch str length "error"
    pass
class WordTooLongError(Exception): # catch ridiculously long strs
    pass

### User birth month input function ###
def get_birth_month():
    """Gets user input as an int in the range 1 to 12, to be used as basis of 
    encryption key. Expected input is str of 1- or 2- digits. Expected output 
    is str of 2-chars and hashed key. Error handling catches whitespace, 
    non-ints, and 1-char strs.

    Returns:
        str: Birth month as 2-char str.
    """
    while True: # repeat until valid input obtained
        try:
            month_int = int(input('Enter your birth month (1-12): '))
            if 1 <= month_int <= 12:
                birth_month = str(month_int)
                print(f'Thank you. '+
                      f'Valid input of "{birth_month}" has been processed.')
                if len(birth_month) < 2:
                    raise OneCharBirthMonthError
            else: # catch any number which isn't an int in correct range
                print(f'Please enter a whole number between 1 and 12.')
                continue # restart loop if input is invalid
        except ValueError: # catch non-numerical str input
            print(f'Invalid input. Please enter a valid birth month (1-12).')
            print(f'For example, January is 1 and December is 12.')
            continue # restart loop if input is invalid
        except EmptyStringError: # refuse to accept whitespace as input
            print(f'Empty input. Please enter a valid number.')
            continue # restart loop if input is invalid
        except OneCharBirthMonthError: # ensure birth month is 2-char format
            birth_month = '0'+birth_month # add leading zero to 1-char month
        return birth_month

### Generate strong derived key from weak key ###    
def generate_key_from_birth_month(birth_month):
    """Generate strong derived key from user birth month using PBKDF2. 
    Expected input is a str. Expected output is a byte object.

    Args:
        birth_month (str): 2-char numerical string.

    Returns:
        bytes: 32-byte strong derived key.
    """    
    salt = token_bytes(16) # generate random 16-byte string
    derived_key = PBKDF2(password=birth_month, salt=salt, 
                        dkLen=32, count=1000000, 
                        hmac_hash_module=SHA512) # hash birth month with salt
    return derived_key

### User word input function ###
def get_word_to_encrypt():
    """Gets user input as single word str for encryption. Expected input is a 
    str. Expected output is a str. Error handling catches whitespace and 
    overly long words.

    Returns:
        string: Plaintext word.
    """    
    while True: # repeat until valid input obtained
        try:
            user_text = input('Enter a single word to encrypt: ')
            user_text = user_text.strip() # remove leading/trailing whitespace
            if user_text=='': # check for empty/whitespace input
                raise EmptyStringError
            elif ' ' in user_text: # check for spaces (multiple words)
                print(f'Invalid input. Multiple words are not accepted.')
                continue # restart loop if input is invalid
            elif len(user_text) > 45: # check for overly long "word"
                raise WordTooLongError
            elif not user_text.isalpha(): # catch non-alphabet chars eg $£%
                print(f'User entered non-alphabet chars.')
                print(f'This program doesn\'t know every word but that '+
                      f'probably isn\'t one.')
                print(f'Please enter letters (Aa-Zz) to spell a word eg '+
                      f'"Python".')
            else: 
                print(f'Thank you. Valid input of "{user_text}" has been '+
                      f'processed.')
                return user_text
        except EmptyStringError: # refuse to accept whitespace as input
            print(f'Empty input. Please enter a valid word.')
            continue # restart loop if input is invalid
        except WordTooLongError: # catch trolling; words are usually <45-chars
            print(f'The longest English word is '+
                  f'pneumonoultramicroscopicsilicovolcanoconiosis.')
            print(f'Please enter a word that is 45-chars or shorter in '+
                  f'length.')
            continue # restart loop if input is unreasonably long

### Function to encrypt word with AES256 in CBC mode ###
def encrypt_data(data, key):
    """Encrypts the plaintext, using relevant key. NB: key arg should be 
    strong key derived from weak birth month. Birth months are weak sauce, 
    even if padded to 32-byte length.

    Args:
        data (string): Word to encrypt.
        key (bytes): Strong key derived from birth month.

    Returns:
        tuple: (ciphertext, iv) Encrypted ciphertext and initialisation 
        vector.
    """    
    data_bytes = data.encode('utf-8')  # encode str as byte obj
    iv = token_bytes(16) # random initialisation vector
    cipher = AES.new(key, AES.MODE_CBC, iv) # AES cipher object in CBC mode
    padded_data = pad(data_bytes, AES.block_size, 
                      style='pkcs7') # pad data to multiple of block size
    ciphertext = cipher.encrypt(padded_data) # encrypt data with CBC
    return ciphertext, iv 
    # NB: Ciphertext & IV typically transmitted together under AES.

### Function to decrypt word with AES256 in CBC mode ###
def decrypt_data(ciphertext, iv, key):
    """Decrypts the ciphertext, assuming prior knowledge of IV and key. NB: 
    key arg must be the same key that was used to encrypt the data ie the 
    strong derived key.

    Args:
        ciphertext (bytes): Encrypted word.
        iv (bytes): Initialisation vector.
        key (bytes): Strong key derived from birth month.

    Returns:
        string: Plaintext word.
    """    
    cipher = AES.new(key, AES.MODE_CBC, iv) # AES cipher object in CBC mode
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size, 
               style='pkcs7') # return data to unpadded size
    plaintext = plaintext.decode('utf-8') # decode byte obj to str
    return plaintext

### Function to nicely present program output ###
def print_output(iv, ciphertext, derived_key, plaintext):
    """Outputs the contents of text storage files, to mimic IRL data 
    transmission. This serves to demonstrate the functionality of the 
    encryption process, while not endorsing unsafe IRL practices. Also prints 
    decrypted plaintext.

    Args:
        iv (bytes): Initialisation vector.
        ciphertext (bytes): Encrypted ciphertext.
        derived_key (bytes): Strong derived key.
        plaintext (str): Plaintext word.
    """    
    line_separator = '»————⋆◦★◦⋆————«»————⋆◦★◦⋆————«»————⋆◦★◦⋆————«'
    # ASCII line art credit: https://copy-paste.net/en/text-dividers.php

    print()
    print(f'{line_separator}')
    print()
    print(f'Warning: birth month is not a secure key or a good basis for '+
          f'KDF.')
    print(f'The birth month was hashed with a random salt to generate a '+
          f'stronger key. :)')
    print()
    print(f'{line_separator}')
    print()
    print(f'The ciphertext and IV have been stored in "cipher.txt"...')
    print(f'The decryption key has been stored in "key.txt"...')
    print()
    print(f'Warning: Keys should be securely stored IRL.')
    print(f'File handling in this demo should not be replicated IRL.')
    print()
    print(f'{line_separator}')
    print()
    print(f'NB: IRL, the ciphertext and IV would be transmitted together.')
    print(f'The encrypted ciphertext is... \n->> {ciphertext}')
    print(f'The initialisation vector (IV) is... \n->> {iv}\n')
    print(f'Warning: *never* expose keys IRL. Keys must be kept secure!')
    print(f'Sshh... this is the super secret secure key... \n->> '+
          f'{derived_key}\n')
    print(f'The decrypted plaintext is... obviously "{plaintext}".')
    print()
    print(f'{line_separator}')
    print()

### I/O functions ###
'''
The sleep function is used to add time delays, enhancing the user experience.
'''
def write_derived_key_to_file(derived_key):
    """Write the derived key to text file, to mimic storing key securely.

    Args:
        derived_key (bytes): 32-byte strong key derived from user birth month.
    """    
    with open('key.txt', 'wb') as file: # wb mode for writing bytes
        file.write(derived_key)
        print(f'Derived key successfully stored. Processing...')
        sleep(2) # pause output for 2 seconds
def read_derived_key_from_file():
    """Read the derived key from text file, to mimic secure key retrival.

    Returns:
        bytes: 32-byte strong key derived from user birth month.
    """    
    try:
        with open('key.txt', 'rb') as file: # rb mode for reading bytes
            derived_key = file.read()
            print(f'Derived key successfully retrieved. Processing...')
            sleep(2) # pause output for 2 seconds
            return derived_key
    except FileNotFoundError:
        print(f'File not found. Did you accidentally delete "key.txt"?')
        exit() # end program prematurely
    except:
        print(f'Unexpected error.')
        exit() # end program prematurely
def write_ciphertext_and_iv_to_file(ciphertext, iv):
    """Write the ciphertext and IV to text file, to mimic data transmission.

    Args:
        ciphertext (bytes): Encrypted ciphertext.
        iv (bytes): Initialisation vector.
    """    
    with open('cipher.txt', 'wb') as file: # wb mode for writing bytes
        file.write(iv) # IV at start of file for retrieval convenience
        file.write(ciphertext)
        print(f'Ciphertext and IV successfully stored. Processing...')
        sleep(2) # pause output for 2 seconds
def read_ciphertext_and_iv_from_file():
    """Read the ciphertext and IV from text file, to mimic data retrieval.

    Returns:
        tuple: (iv, ciphertext) Initialisation vector and ciphertext.
    """    
    try:
        with open('cipher.txt', 'rb') as file: # rb mode for reading bytes
            iv = file.read(16) # IV is first 16 bytes in order of writing
            ciphertext = file.read()
            print(f'Ciphertext and IV successfully retrieved. Processing...')
            sleep(2) # pause output for 2 seconds
            return iv, ciphertext
    except FileNotFoundError:
        print(f'File not found. Did you accidentally delete "cipher.txt"?')
        exit() # end program prematurely
    except:
        print(f'Unexpected error.')
        exit() # end program prematurely

if __name__ == '__main__': # run as standalone program
    '''
    Once upon a time... in the land where the knights say "Ni!"...
    Use your imagination because this demo stores everything locally in 
    unencrypted text files. Maybe the key is really in a top secret, highly 
    secure data vault!
    '''

    birth_month = get_birth_month() # get user birth month
    derived_key = generate_key_from_birth_month(birth_month) # gen derived key
    write_derived_key_to_file(derived_key) # "securely" store top secret key

    plaintext = get_word_to_encrypt() # get user word to encrypt
    key = read_derived_key_from_file() # access "secure" top secret key

    ciphertext, iv = encrypt_data(plaintext, key) # encrypt word
    write_ciphertext_and_iv_to_file(ciphertext, iv) # "transmit" ciphertext/IV

    # "receiving" ciphertext & IV (below)
    retrieved_iv, retrieved_ciphertext = read_ciphertext_and_iv_from_file()
    plaintext_result = decrypt_data(
        retrieved_ciphertext, retrieved_iv, derived_key
        ) # decrypt word

    print_output(iv, ciphertext, derived_key, plaintext_result) # it works!
    
    # they think it's all over...    
else: # catch use as module import
    print(f'I think you imported this file by mistake!') 
# ...it is now!
