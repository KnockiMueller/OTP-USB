import os

def decrypt(filename, keyf):
    file = open(filename, 'rb').read()
    key = open(keyf, 'rb').read()
    decrypted = bytes(a^b for(a, b) in zip(file, key))
    os.remove(filename)
    filename = f'{filename.split(".")[0]}.{filename.split(".")[1]}'
    with open(filename, 'wb') as decrypted_out:
        decrypted_out.write(decrypted)
    os.remove(keyf)

