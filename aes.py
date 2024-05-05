import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def decrypt_file(file_path, key, mode):
    # Путь к выходному файлу с расшифрованным содержимым
    output_file_path = file_path.replace('.aes', '')

    modes = {
        'cbc': AES.MODE_CBC,
        'ecb': AES.MODE_ECB,
        'cfb': AES.MODE_CFB,
        'ofb': AES.MODE_OFB
    }

    if mode not in modes:
        raise ValueError('Неверный режим работы AES. Допустимые режимы: {}'.format(list(modes.keys())))

    # Чтение IV из зашифрованного файла
    with open(file_path, 'rb') as file:
        iv = file.read(AES.block_size)
        encrypted_data = file.read()

    # Создание AES cipher в указанном режиме
    try:
        cipher = AES.new(key.encode(), modes[mode], iv=iv)
    except ValueError as e:
        print(f'Ошибка: {e}')
        return

    # Расшифрование данных
    try:
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    except ValueError as e:
        print(f'Ошибка: {e}')
        return

    # Сохранение расшифрованных данных в файл
    with open(output_file_path, 'wb') as file:
        file.write(decrypted_data)

    return output_file_path


def encrypt_file(file_path, key, algorithm):
    # Путь к выходному файлу с зашифрованным содержимым
    output_file_path = file_path + '.aes'

    modes = {
        'cbc': AES.MODE_CBC,
        'ecb': AES.MODE_ECB,
        'cfb': AES.MODE_CFB,
        'ofb': AES.MODE_OFB
    }

    if algorithm not in modes:
        raise ValueError('Неверный режим работы AES. Допустимые режимы: {}'.format(list(modes.keys())))

    # Создать AES cipher в указанном режиме
    cipher = AES.new(key.encode(), modes[algorithm])

    # Чтение и шифрование данных из файла
    with open(file_path, 'rb') as file:
        plaintext_data = file.read()

    # Добавление padding к данным, если это необходимо
    padded_data = pad(plaintext_data, AES.block_size)

    # Шифрование данных
    encrypted_data = cipher.encrypt(padded_data)

    # Сохранить зашифрованные данные и IV в файл
    with open(output_file_path, 'wb') as file:
        file.write(cipher.iv)
        file.write(encrypted_data)

    return output_file_path


parser = argparse.ArgumentParser(description='Шифрование или расшифрование файла с использованием AES')
parser.add_argument('-m', '--mode', help='Режим работы AES (encrypt/decrypt)', required=True)
parser.add_argument('-a', '--algorithm', help='Режим работы AES (cbc/ecb/cfb/ofb)', required=True)
parser.add_argument('file_path', help='Путь к файлу, который нужно зашифровать/расшифровать')
parser.add_argument('key', help='Ключ шифрования (байтовый массив)')

# Получение аргументов командной строки
args = parser.parse_args()


# Выбор режима в зависимости от указанного пользователем параметра
if args.mode == 'encrypt':
    encrypted_file_path = encrypt_file(args.file_path, args.key, args.algorithm)
    print(f'Файл зашифрован. Имя файла {encrypted_file_path}')
elif args.mode == 'decrypt':
    decrypted_file_path = decrypt_file(args.file_path, args.key, args.algorithm)
    print(f'Файл расшифрован. Имя файла {decrypted_file_path}')
else:
    print('Неверный режим работы. Допустимые режимы: encrypt/decrypt')
