import decryption
import encryption
import os


def encrypt(id, path, kpath):
    fileName = getPath(id, path)
    encryption.encrypt(fileName, kpath)
    print(f"Encrypted: new files:")
    print(f"- {fileName}.crypt")
    fileName = fileName.split('\\')[1]
    print(f"- {kpath}\\{fileName}.key")
    print('-----------')


def decrypt(file, key):
    return decryption.decrypt(file, key)


def start():
    print('Starting...')
    e = False
    ecodes = ''
    try:
        f = open('setup.txt', 'r')
        t = f.readlines()
        f.close()
        user = t[0].replace('\n', '')
        folder = t[1].replace('\n', '')
        key = t[2].replace('\n', '')
        e = True

        if not os.path.exists(folder):
            ecodes = 1
            e = False

        if not os.path.exists(key):
            ecodes = 1
            e = False

    except FileNotFoundError:
        ecodes = 0
        e = False

    if not e:
        pe = False
    else:
        pe = True
        print('Successful started')
    try:
        return user, folder, key, pe, ecodes
    except:
        return 'Error', 'Error', 'Error', False, 0


def bugfix():
    v = True
    print('!!! Notice: !!! \nIf the paths you enter are wrong, your files will be encrypted forever or until you find the keys. '
          '\nSo overcheck everything.\n!!!!!!!!!!!!!!!!')
    user = input('Please enter a user name: ')
    file = input('Please enter the file path: ')
    keys = input('Please enter the key path: ')
    print('Checking input...')
    if os.path.exists(file):
        if os.path.exists(keys):
            print('Valid input')
            with open('setup.txt', 'w') as f:
                f.write(f'{user}\n{file}\n{keys}')
        else:
            print('Invalid path key path...')
            v = False
    else:
        print('Invalid path file path...')
        v = False

    return v


def question(answers, q):
    f = False
    answers = answers
    while not f:
        answer = str(input(q))
        if answer in answers:
            f = True
            return answer
        else:
            print('Invalid answer')


def getPath(index, path):
    dir_list = os.listdir(path)
    fn = dir_list[index]
    fn = f'{path}\\{fn}'

    return fn


def update(folder):
    mode = []
    datas = os.listdir(folder)
    dec = ['decrypted', 'encrypted']
    for i in range(len(datas)):
        try:
            if datas[i].split('.')[2] == 'crypt':
                mode.append(dec[1])
        except:
            if datas[i].split('.')[1] != 'crypt':
                mode.append(dec[0])
    return mode


def liste(folder):
    mode = []
    datas = os.listdir(folder)
    dec = ['decrypted', 'encrypted']
    for i in range(len(datas)):
        try:
            if datas[i].split('.')[2] == 'crypt':
                print(f'[{i}] - {dec[1]} - {datas[i]}')
                mode.append(dec[1])
        except:
            if datas[i].split('.')[1] != 'crypt':
                print(f'[{i}] - {dec[0]} - {datas[i]}')
                mode.append(dec[0])
    return mode


def running():
    user, data_folder, key_folder, run, ec = start()
    commands = ['enc', 'dec', 'exit', 'list', 'help']
    if run:
        print(f'These are the Datas in "{data_folder}":')
        modes = liste(data_folder)
        print('---------------')

    if not run:
        print('\n----------------')
        print('Error Code:')
        if ec == 0:
            print('- 00: "setup.txt" does not exist')
        elif ec == 1:
            print('- 01: invalid path in "setup.txt"')

        print('----------------\n')

        bugfi = question(['y', 'n'], 'Do you want to try to fix the problem? (y/n): ')
        if bugfi == 'y':
            v = bugfix()
            if v:
                s = question(['y', 'n'], 'Do you want to start the program now? (y/n): ')
                if s == 'y':
                    print('Trying to start...\n')
                    user, data_folder, key_folder, run, ec = start()
                    if run:
                        print(f'These are the Datas in "{data_folder}":')
                        modes = liste(data_folder)
                        print('---------------')

    while run:
        try:
            c = input(f"helper\\{user}\\")
            c = c.lower()
            if c in commands:
                # ---- Encryption ----
                if c == 'enc':
                    answer = ''
                    print('-----------\nEncrypt')
                    data = int(input('Enter the ID of the data you want to encrypt: '))
                    if modes[int(data)] == 'encrypted':
                        answer = question(['y', 'n'], 'This data already seems to be encrypted. Do you really want to encrypt this data? (y/n) ')
                        if answer == 'y':
                            encrypt(data, data_folder, key_folder)
                    else:
                        encrypt(data, data_folder, key_folder)
                    modes = update(data_folder)
                # --------------------

                # ---- Decryption ----
                if c == 'dec':
                    answer = ''
                    print('-----------\nDecrypt')
                    data = int(input('Enter the ID of the data you want to decrypt: '))
                    filef = getPath(data, data_folder)
                    keyf = key_folder + '\\' + getPath(data, data_folder).split("\\")[1].split(".")[0] + '.' + getPath(data, data_folder).split(".")[1] + '.key'
                    if modes[int(data)] == 'decrypted':
                        answer = question(['y', 'n'], 'This data already seems to be decrypted. Do you really want to decrypted this data? (y/n) ')
                        if answer == 'y':
                            decrypt(filef, keyf)
                            print(f'Decrypted. New file: {filef.split(".")[0]}.{filef.split(".")[1]}')
                    else:
                        decrypt(filef, keyf)
                        print(f'Decrypted. New file: {filef.split(".")[0]}.{filef.split(".")[1]}\n-----------')
                    modes = update(data_folder)
                # --------------------

                # ---- Exit ----
                if c == 'exit':
                    answer = ''
                    run = False
                    print('Exit')
                # ----------------

                # ---- Listing ----
                if c == 'list':
                    modes = liste(data_folder)
                # -----------------

                if c == 'help':
                    print('------ Helper ------')
                    print('Dec: The Decryption function.\nEnc: The Encryption function.\nList: That function lists the '
                          'content of the folder.\nExit: Closes the program.')
                    print('--------------------')
        except:
            print('Error')
            continue


running()
