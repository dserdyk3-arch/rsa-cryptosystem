#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Практическая работа №7
Криптосистемы с открытым ключом (RSA)

Д.О. Сердюк
Группа МКБ251
НИУ ВШЭ, МИЭМ, 2026
"""

import secrets
import os


# ============================================================
# 1. Тест Миллера–Рабина
# ============================================================

def miller_rabin(n: int, k: int = 20) -> bool:
    """
    Вероятностная проверка числа n на простоту.
    Вероятность ошибки не превышает 2^(-k).
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    r = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits: int = 512) -> int:
    """Генерация простого числа заданной битовой длины."""
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if miller_rabin(candidate):
            return candidate


# ============================================================
# 2. Расширенный алгоритм Евклида и НОД
# ============================================================

def gcd_extended(a: int, b: int):
    """Расширенный алгоритм Евклида: возвращает (gcd, x, y)"""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = gcd_extended(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def mod_inverse(e: int, phi: int) -> int:
    """Находит обратный элемент e по модулю phi"""
    gcd, x, _ = gcd_extended(e, phi)
    if gcd != 1:
        raise ValueError("Обратный элемент не существует")
    return x % phi


def gcd(a: int, b: int) -> int:
    """Вычисляет НОД(a, b) без использования math.gcd"""
    while b != 0:
        a, b = b, a % b
    return a


# ============================================================
# 3. Генерация и сохранение ключей
# ============================================================

def generate_keys(bits: int = 512, e: int = 65537):
    """Генерация пары ключей RSA."""
    print("Генерация простых чисел...")
    p = generate_prime(bits)
    q = generate_prime(bits)
    while p == q:
        q = generate_prime(bits)

    n = p * q
    phi = (p - 1) * (q - 1)

    # Проверяем, что e и phi взаимно просты (через свою функцию gcd)
    if gcd(e, phi) != 1:
        raise ValueError("e не взаимно просто с φ(n)")

    d = mod_inverse(e, phi)

    print("Ключи успешно сгенерированы.")
    return (e, n), (d, n)


def save_keys(public_key, private_key, pub_file="public_key.txt", priv_file="private_key.txt"):
    """Сохраняет ключи в файлы."""
    e, n = public_key
    d, _ = private_key
    with open(pub_file, "w") as f:
        f.write(f"{e}\n{n}\n")
    with open(priv_file, "w") as f:
        f.write(f"{d}\n{n}\n")
        f.write("# KEEP THIS FILE SECRET!\n")
    print(f"Открытый ключ сохранён в {pub_file}")
    print(f"Закрытый ключ сохранён в {priv_file}")


def load_public_key(filename="public_key.txt"):
    """Загружает открытый ключ из файла."""
    with open(filename, "r") as f:
        e = int(f.readline().strip())
        n = int(f.readline().strip())
    return (e, n)


def load_private_key(filename="private_key.txt"):
    """Загружает закрытый ключ из файла."""
    with open(filename, "r") as f:
        d = int(f.readline().strip())
        n = int(f.readline().strip())
    return (d, n)


# ============================================================
# 4. Шифрование и расшифрование
# ============================================================

def encrypt(message: bytes, e: int, n: int):
    block_size = (n.bit_length() - 1) // 8
    if block_size < 1:
        block_size = 1

    cipher_blocks = []
    for i in range(0, len(message), block_size):
        block = message[i:i + block_size]
        m = int.from_bytes(block, byteorder="big")
        if m >= n:
            raise ValueError("Блок сообщения слишком велик для данного модуля")
        c = pow(m, e, n)
        cipher_blocks.append(c)
    return cipher_blocks


def decrypt(cipher_blocks, d: int, n: int):
    decrypted = b''
    for c in cipher_blocks:
        m = pow(c, d, n)
        block = m.to_bytes((m.bit_length() + 7) // 8, byteorder="big")
        decrypted += block
    return decrypted


# ============================================================
# 5. Работа с файлами
# ============================================================

def encrypt_file(input_file, output_file, public_key):
    e, n = public_key
    with open(input_file, "rb") as f:
        data = f.read()
    cipher = encrypt(data, e, n)
    with open(output_file, "w") as f:
        f.write(",".join(map(str, cipher)))
    print("Файл успешно зашифрован.")


def decrypt_file(input_file, output_file, private_key):
    d, n = private_key
    with open(input_file, "r") as f:
        cipher = list(map(int, f.read().split(",")))
    decrypted = decrypt(cipher, d, n)
    with open(output_file, "wb") as f:
        f.write(decrypted)
    print("Файл успешно расшифрован.")


# ============================================================
# 6. Атака на малую экспоненту e=3
# ============================================================

def attack_small_e():
    print("\n=== Атака при e = 3 ===")
    m = 42
    e = 3
    n = 100000
    c = pow(m, e, n)
    recovered = round(c ** (1 / 3))
    print(f"Исходное сообщение: {m}")
    print(f"Шифртекст: {c}")
    print(f"Восстановлено извлечением кубического корня: {recovered}")
    if recovered == m:
        print("Атака успешна!")
    else:
        print("Атака не удалась.")


# ============================================================
# 7. Ручная демонстрация (из отчёта)
# ============================================================

def manual_demo():
    print("\n=== Ручная демонстрация (из отчёта) ===")
    p, q = 61, 53
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 17
    d = mod_inverse(e, phi)

    print(f"p = {p}, q = {q}")
    print(f"n = {n}, φ(n) = {phi}")
    print(f"e = {e}, d = {d}\n")

    text = "HSEMOSCOW26"
    print(f"Открытый текст: {text}")

    ascii_codes = [ord(ch) for ch in text]
    print(f"ASCII коды: {ascii_codes}")

    cipher = [pow(m, e, n) for m in ascii_codes]
    print(f"Шифртекст: {cipher}")

    decrypted_codes = [pow(c, d, n) for c in cipher]
    decrypted_text = ''.join(chr(code) for code in decrypted_codes)
    print(f"Расшифрованный текст: {decrypted_text}\n")
    print("Демонстрация завершена.")


# ============================================================
# 8. Меню
# ============================================================

def main():
    public_key = None
    private_key = None

    while True:
        print("\n" + "=" * 50)
        print("RSA CRYPTOSYSTEM")
        print("Практическая работа №7")
        print("Д.О. Сердюк, МКБ251")
        print("=" * 50)
        print("1. Сгенерировать и сохранить ключи")
        print("2. Загрузить ключи из файлов")
        print("3. Зашифровать файл")
        print("4. Расшифровать файл")
        print("5. Атака на e = 3 (не перебор)")
        print("6. Ручная демонстрация (из отчёта)")
        print("0. Выход")

        choice = input("Выбор: ").strip()

        if choice == "1":
            bits = input("Разрядность ключа (по умолчанию 512): ").strip()
            bits = int(bits) if bits else 512
            e_val = input("Значение e (по умолчанию 65537): ").strip()
            e_val = int(e_val) if e_val else 65537
            public_key, private_key = generate_keys(bits, e_val)
            save_keys(public_key, private_key)

        elif choice == "2":
            try:
                public_key = load_public_key()
                private_key = load_private_key()
                print("Ключи успешно загружены.")
            except FileNotFoundError:
                print("Файлы с ключами не найдены. Сначала сгенерируйте ключи (п.1).")

        elif choice == "3":
            if public_key is None:
                print("Нет загруженных ключей. Сгенерируйте или загрузите ключи.")
            else:
                encrypt_file("input.txt", "encrypted.txt", public_key)

        elif choice == "4":
            if private_key is None:
                print("Нет загруженных ключей. Сгенерируйте или загрузите ключи.")
            else:
                decrypt_file("encrypted.txt", "decrypted.txt", private_key)

        elif choice == "5":
            attack_small_e()

        elif choice == "6":
            manual_demo()

        elif choice == "0":
            print("До свидания!")
            break

        else:
            print("Неверный выбор. Попробуйте снова.")


if __name__ == "__main__":
    main()
