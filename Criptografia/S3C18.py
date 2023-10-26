from Crypto.Cipher import AES
import struct
from base64 import b64decode


def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

def PKCS7_pad(string, blocksize):
    '''Função para aplicar Padding PKCS7'''    
    if len(string) == blocksize:
        return string
    
    padding = blocksize - len(string) % blocksize
    
    res = string + bytes([padding] * (padding))
    
    return res

def PKCS7_unpad(string):
    '''Função específica para realizar o Unpadding de PKCS7'''
    padding = string[-1]
    if padding > 16:
        raise Exception('Invalid padding')
    
    for i in range(1, padding + 1):
        if string[-i] != padding:
            raise Exception('Invalid padding')
    
    return string[:-padding]

#Aplicação da Criptografia por ECB usando AES em um único bloco
def AES_ECB_encrypt(data, key):
    '''Aplicação da Criptografia por ECB usando o Advanced Encryption Standard, Nesse caso se aplica a chave por bloco de plaintext'''
    key = bytes(key, encoding='utf-8')
    cipher = AES.new(key, AES.MODE_ECB)

    #Necessário "preencher" os dados para se encaixar no bloco

    encrypt_data = PKCS7_pad(data, AES.block_size)
    
    
    return cipher.encrypt(encrypt_data)

def AES_ECB_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    #Necessaŕio descriptografar para depois adicionar o preenchimento
    descrypted_data = cipher.decrypt(ciphertext)
    return PKCS7_unpad(descrypted_data)

def AES_CTR_encrypt(plaintext, key, nonce):
    '''Aplicação de CTR usando como base ECB'''
    ciphertext = b''
    counter = 0

    for i in range(0, len(plaintext), len(key)):
        #Realizando a divisão de blocos de plaintext
        block = plaintext[i: i + len(key)]
        nonce_e_counter = struct.pack("<QQ", nonce, counter)

        #Criptografia do nonce+counter e key
        encrypted = AES_ECB_encrypt(nonce_e_counter, key)

        new_cipher = xor(block, encrypted)

        counter += 1
        #Incrementar cipher
        ciphertext += new_cipher

    return ciphertext


def main():
    text = b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
    key = "YELLOW SUBMARINE"
    nonce = 0

    print(AES_CTR_encrypt(text, key, nonce))

if __name__ == "__main__":
    main()
