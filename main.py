import decryption
import encryption
import os
import AES


# --- AES Cipher ---
def encAES(p, k_path):
    """
    Encryption of the keys with the AES cipher
    :param p: for encrypting the data
    :param k_path: path were the keys are stored
    :return:
    """
    af = allFiles(k_path)

    for file in af:
        AES.encrypt(AES.get_key(p), file)
        os.remove(file)


def decAES(p, k_path):
    """
    Decrypting the keys with the AES cipher
    :param p: for decrypting the data
    :param k_path: path were the keys are stored
    :return:
    """

    r = True

    c_path = f'{k_path}\\control.txt'
    ce_path = f'{k_path}\\encrypted-control.txt'

    if not os.path.exists(c_path):
        if not os.path.exists(ce_path):
            with open(c_path, 'wb') as f:
                f.write(b'Control String')

    temp_control = b''
    c = b''

    if os.path.exists(ce_path):
        with open(ce_path, 'rb') as f:
            temp_control = f.readlines()

        AES.decrypt(AES.get_key(p), ce_path)

        with open(c_path, 'rb') as f:
            c = f.readlines()


        if c[0] == b'Control String':
            r = True
            os.remove(ce_path)
        else:
            os.remove(c_path)
            with open(ce_path, 'wb') as f:
                f.write(temp_control[0])
            r = False

    if r:
        af = allFiles(k_path)
        for file in af:
            if 'encrypted-' in file:
                AES.decrypt(AES.get_key(p), file)
                os.remove(file)

    return r


# -------
# --- OTP Cipher ---
def encrypt(id, path, kpath):
    """

    :param id: ID of file that's gonna be encrypted
    :param path: path of the folder
    :param kpath: path of the key
    :return:
    """
    fileName = getPath(id, path)
    print(fileName)
    now = kpath
    for i in fileName.split('\\')[1:-1]:
        now = now + '\\' + i
        try:
            os.makedirs(now)
        except FileExistsError:
            continue

    encryption.encrypt(fileName, kpath)
    print(f"Encrypted: new files:")
    print(f"- {fileName}.crypt")
    fileName = ''.join(fileName.split('\\')[1:])
    print(f"- {kpath}\\{fileName}.key")
    print('-----------')


def decrypt(file, key):
    """

    :param file: file name and path
    :param key: key for decryption
    :return:
    """
    return decryption.decrypt(file, key)


# ----------

# --- Commandline Functions ---
def start():
    """
    Reads Setup.txt and returns important varaibles
    :return: user, folder, key, Error and Errorcodes
    """
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
    """
    Short Bugfix for writing setup.txt
    - User
    - Folder operating in (Start)
    - Path for keys being stored
    :return: Successful bugfix
    """
    v = True
    print(
        '!!! Notice: !!! \nIf the paths you enter are wrong, your files will be encrypted forever or until you find the keys. '
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
    """
    Loop for questions where answer needed
    :param answers: possible answers
    :param q: question
    :return: answer
    """
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
    """
    Searching for filename of file determined with the index
    :param index: Index of the file
    :param path: Folder operating in
    :return: filename combined with index
    """
    m, f = liste(path)

    return f'{path}\\{f[index]}'


def liste(folder, pr=False, dirc=False):
    """
    Lists the files and their status (encrypted or decrypted)
    :param dirc: list of the folders
    :param pr: Abfrage ob ausgegeben werden soll
    :param folder: folder operating in
    :return: list of modes
    """
    mode = []
    files_l = []
    d = []
    f = []
    dec = ['decrypted', 'encrypted']
    c = 0
    for (root, dirs, files) in os.walk(folder):
        f.append(files)
        d.append(dirs)

    f = f[0]

    for file in f:
        files_l.append(file)
        if '.crypt' in file:
            if pr:
                print(f'[{c}] - {dec[1]} - {file}')
            mode.append(dec[1])
        else:
            if pr:
                print(f'[{c}] - {dec[0]} - {file}')
            mode.append(dec[0])

        c += 1

    if dirc:
        return d
    return mode, files_l


def allFiles(start, ty='files'):
    inhalt = os.walk(start)
    if ty == 'files':
        files = []
        for u in inhalt:
            for file in u[2]:
                files.append(f'{u[0]}\\{file}')

        return files

    if ty == 'folders':
        folder = []
        for u in inhalt:
            folder.append(u[0])
        return folder

# --------

def running():
    user, data_folder, key_folder, run, ec = start()
    commands = ['enc', 'dec', 'exit', 'list', 'help', 'open', 'close', 'nk', 'encAES']
    modes = []
    files = []
    root = data_folder
    print(root)
    if run:
        print(f'These are the files in "{data_folder}":')
        modes, files = liste(data_folder, True)
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
                        print(f'These are the files in "{data_folder}":')
                        modes, files = liste(data_folder, pr=True)
                        print('---------------')

    mp = ''
    mp_r = False
    if run:
        epwd = 'pwd1234'  # am besten leicht abweichend von master-passwort -> verschlüsselt erst im Nachhinein
        epwdfe = ''
        delpwd = 'pwd1238'  # Löscht sofort alles
        while not mp_r and run:
            mp = input('Enter the master key for decrypting the keys: ')

            if mp == epwd:
                epwd = True
                epwdfe = input('Enter the master key for decrypting the keys: ')

            if mp == 'quit':
                run = False
                continue

            if mp == delpwd:
                a = allFiles(root)
                for i in a:
                    os.remove(i)
                run = False

            mp_r = decAES(mp, key_folder)

        while run:
            c = input(f"helper\\{user}\\")
            c = c.lower()
            if c in commands:
                # ---- Encryption ----
                if c == 'enc':
                    answer = ''
                    print('-----------\nEncrypt')
                    data = int(input('Enter the ID of the data you want to encrypt: '))
                    if modes[int(data)] == 'encrypted':
                        answer = question(['y', 'n'],
                                          'This data already seems to be encrypted. Do you really want to encrypt this data? (y/n) ')
                        if answer == 'y':
                            encrypt(data, data_folder, key_folder)
                    else:
                        encrypt(data, data_folder, key_folder)
                    modes, files = liste(data_folder)
                # --------------------

                # ---- Decryption ----
                if c == 'dec':
                    if not epwd:
                        answer = ''

                        print('-----------\nDecrypt')

                        data = int(input('Enter the ID of the data you want to decrypt: '))
                        filef = getPath(data, data_folder)

                        print(filef)
                        keyf = '.'.join(filef.split('.')[:-1]) + '.key'
                        keyf = key_folder + '\\' + '\\'.join(keyf.split('\\')[1:])
                        print(keyf)

                        if modes[int(data)] == 'decrypted':
                            answer = question(['y', 'n'],
                                              'This data already seems to be decrypted. Do you really want to decrypted this data? (y/n) ')
                            if answer == 'y':
                                decrypt(filef, keyf)
                                print(f'Decrypted. New file: {filef.split(".")[0]}.{filef.split(".")[1]}')
                        else:
                            decrypt(filef, keyf)
                            print(f'Decrypted. New file: {filef.split(".")[0]}.{filef.split(".")[1]}\n-----------')
                        modes, files = liste(data_folder)
                    else:
                        print('Error')
                # --------------------

                # ---- Exit ----
                if c == 'exit':
                    answer = ''
                    run = False
                    if epwd:
                        encAES(epwdfe, root)
                    if mp_r:
                        if mp == '':
                            mp = input('Enter the master key for encrypting and decrypting the key-files: ')
                        encAES(mp, key_folder)
                    print('Exit')
                # ----------------

                # ---- Listing ----
                if c == 'list':
                    modes, files = liste(data_folder, pr=True)
                # -----------------

                # ---- Help ----
                if c == 'help':
                    print('------ Helper ------')
                    print('Dec: The Decryption function.\nEnc: The Encryption function.\nList: That function lists the '
                          'content of the folder.\nExit: Closes the program.')
                    print('--------------------')
                # -----------------

                # ---- Open ----
                if c == 'open':
                    dirs = liste(data_folder, dirc=True)[0]
                    print(f'These are the Folders in "{data_folder}":')
                    ind = []
                    for i in range(len(dirs)):
                        ind.append(str(i))
                        print(f'[{i}] - {dirs[i]}')
                    print('---------------')
                    ind.append('quit')
                    answer = question(ind, "Which folder do you want to open? (Type the index or quit) ")

                    if answer != 'quit':
                        data_folder = f'{data_folder}\\{dirs[int(answer)]}'
                        print('--------')
                        print(f'OK, now operating in {data_folder}\n')
                        print(f'These are the files in "{data_folder}":')
                        modes, files = liste(data_folder, True)
                        print('---------------')
                # -----------------

                # ---- Close ----
                if c == 'close':
                    if len(data_folder.split('\\')) == 1:
                        print('Operating in Main-Folder')
                    else:
                        data_folder = ''.join(data_folder.split('\\')[:-1])
                        print('--------')
                        print(f'OK, now operating in {data_folder}\n')
                        print(f'These are the files in "{data_folder}":')
                        modes, files = liste(data_folder, True)
                        print('---------------')
                # -----------------

                # ---- nk (new Key) ----
                if c == 'nk':
                    t = False
                    p = True
                    while p:
                        while not t and p:
                            old_key = input('Enter old key: ')
                            if old_key == mp:
                                print('Verified old key...')
                                t = True

                            if old_key == 'quit':
                                p = False
                                print('Quit')

                        t = False

                        while not t and p:
                            nk = input('Enter new key: ')
                            old_key = input('Verify new key: ')
                            if nk == 'quit' or old_key == 'quit':
                                p = False
                                print('Quit')

                            if nk == old_key:
                                print('Verified new key...')
                                mp = nk
                                print('New key changed.')
                                p = False
                # -----------------


if __name__ == '__main__':
    running()
