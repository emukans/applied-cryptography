# Applied Cryptography

## Requirements
1. Python 3.7 (Tested on 3.7.5)
2. cryptography 2.8
3. click 7.0
3. python-dotenv 0.10

## Prerequisites
1. Python dependencies. Can be installed via pipenv or pip.
    ```shell script
    pipenv install
    ```
   
## AES block cipher encode/decode
1. Put a message to encode into `message.txt`
2. (optional) generate your binary key if needed and put it into `key` file
3. Encode and decode string using command. Follow prompt messages and select appropriate option.
    ```shell script
    python -m block_cipher
    ```
   
## X.509 certificate generation (HW 2, task 1)
1. (Optional) Change ISSUER variable in `x509/env` file. The value will be used in X.509 certification generation
2. Generate certificate
    ```shell script
    python -m x509 generate 
    ```

## X.509 certificate verification (HW 2, task 2)
1. Run a shell script
    ```shell script
    python -m x509 verify
    ```
   In case of failure, you will see an error message, that signature or issuer/subject is incorrect.
   
## X.509 message encrypt/decrypt (HW 2, task 3)
1. Put a message into `x509/message.txt` file
2. Run a shell script to encrypt the message
    ```shell script
    python -m x509 encrypt
    ```
3. To decrypt the message run command
    ```shell script
    python -m x509 decrypt
    ```
    The initial message will appear in the terminal and will be stored in binary format in `x509/decrypted_message`
