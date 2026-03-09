from flask import Flask, render_template, request, jsonify, session
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import sqlite3
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Секретный ключ для сессий

# Инициализация базы данных
def init_db():
    conn = sqlite3.connect('cipher_history.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS operations
        (id INTEGER PRIMARY KEY AUTOINCREMENT,
         operation_type TEXT,
         cipher_type TEXT,
         timestamp TEXT)
    ''')
    conn.commit()
    conn.close()

init_db()

# Главная страница
@app.route('/')
def index():
    return render_template('index.html')

# Страница "О проекте"
@app.route('/about')
def about():
    return render_template('about.html')

# ============= ФУНКЦИИ ДЛЯ РАБОТЫ С РАЗНЫМИ АЛФАВИТАМИ =============

# Словарь с алфавитами для разных языков
ALPHABETS = {
    'en': 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
    'ru': 'АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдеёжзийклмнопрстуфхцчшщъыьэюя',
    'mixed': None  # Специальный режим для смешанного текста
}

def detect_alphabet(char):
    """Определяет, к какому алфавиту принадлежит символ"""
    if 'A' <= char <= 'Z' or 'a' <= char <= 'z':
        return 'en'
    elif 'А' <= char <= 'Я' or 'а' <= char <= 'я' or char == 'Ё' or char == 'ё':
        return 'ru'
    return None

def caesar_cipher(text, shift, preserve_case=True):
    """
    Шифр Цезаря с поддержкой русского и английского языков
    """
    result = ""
    for char in text:
        # Определяем алфавит символа
        lang = detect_alphabet(char)
        
        if lang == 'en':
            # Английский алфавит
            if char.isupper():
                start = ord('A')
                result += chr((ord(char) - start + shift) % 26 + start)
            else:
                start = ord('a')
                result += chr((ord(char) - start + shift) % 26 + start)
        
        elif lang == 'ru':
            # Русский алфавит (33 буквы + Ё)
            if char in 'Ёё':
                # Особая обработка для буквы Ё
                if char == 'Ё':
                    ru_letters = 'АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ'
                else:
                    ru_letters = 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя'
                
                idx = ru_letters.index(char)
                new_idx = (idx + shift) % 33  # 33 буквы в русском алфавите с Ё
                result += ru_letters[new_idx]
            else:
                # Обычные русские буквы
                if char.isupper():
                    start = ord('А')
                    # Сдвиг с учетом того, что Ё идет отдельно
                    pos = ord(char) - start
                    # Корректировка для букв после Ё
                    if pos >= 6:  # После Ё (позиция 6)
                        pos -= 1  # Ё не входит в непрерывный диапазон
                    new_pos = (pos + shift) % 32
                    # Обратная коррекция
                    if new_pos >= 6:
                        new_pos += 1
                    result += chr(start + new_pos)
                else:
                    start = ord('а')
                    pos = ord(char) - start
                    if pos >= 6:
                        pos -= 1
                    new_pos = (pos + shift) % 32
                    if new_pos >= 6:
                        new_pos += 1
                    result += chr(start + new_pos)
        
        else:
            # Не буква (цифры, знаки препинания) - оставляем как есть
            result += char
    
    return result

def vigenere_cipher(text, keyword, encrypt=True):
    """
    Шифр Виженера с поддержкой русского и английского языков
    Ключевое слово может быть на любом языке, но лучше использовать один язык
    """
    result = ""
    keyword_index = 0
    
    for char in text:
        lang = detect_alphabet(char)
        
        if lang == 'en':
            # Английский текст
            if char.isupper():
                start = ord('A')
                # Определяем сдвиг из ключевого слова
                key_char = keyword[keyword_index % len(keyword)]
                key_lang = detect_alphabet(key_char)
                
                if key_lang == 'en':
                    # Ключ на английском
                    if key_char.isupper():
                        shift = ord(key_char) - ord('A')
                    else:
                        shift = ord(key_char.upper()) - ord('A')
                else:
                    # Если ключ на другом языке, используем фиксированный сдвиг 3
                    shift = 3
                
                if not encrypt:
                    shift = -shift
                
                result += chr((ord(char) - start + shift) % 26 + start)
                keyword_index += 1
            else:
                start = ord('a')
                key_char = keyword[keyword_index % len(keyword)]
                key_lang = detect_alphabet(key_char)
                
                if key_lang == 'en':
                    if key_char.isupper():
                        shift = ord(key_char) - ord('A')
                    else:
                        shift = ord(key_char.upper()) - ord('A')
                else:
                    shift = 3
                
                if not encrypt:
                    shift = -shift
                
                result += chr((ord(char) - start + shift) % 26 + start)
                keyword_index += 1
        
        elif lang == 'ru':
            # Русский текст
            if char in 'Ёё':
                # Особая обработка для Ё
                ru_letters = 'АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ' if char.isupper() else 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя'
                key_char = keyword[keyword_index % len(keyword)]
                
                # Определяем сдвиг из ключа (пытаемся использовать букву ключа)
                key_lang = detect_alphabet(key_char)
                if key_lang == 'ru':
                    if key_char.isupper():
                        if key_char == 'Ё':
                            shift = 6  # Позиция Ё
                        else:
                            shift = ord(key_char) - ord('А')
                            if shift >= 6:
                                shift -= 1
                    else:
                        if key_char == 'ё':
                            shift = 6
                        else:
                            shift = ord(key_char) - ord('а')
                            if shift >= 6:
                                shift -= 1
                else:
                    shift = 3
                
                if not encrypt:
                    shift = -shift
                
                idx = ru_letters.index(char)
                new_idx = (idx + shift) % 33
                result += ru_letters[new_idx]
                keyword_index += 1
            else:
                # Обычные русские буквы
                if char.isupper():
                    start = ord('А')
                    pos = ord(char) - start
                    if pos >= 6:
                        pos -= 1
                    
                    key_char = keyword[keyword_index % len(keyword)]
                    key_lang = detect_alphabet(key_char)
                    
                    if key_lang == 'ru':
                        if key_char.isupper():
                            if key_char == 'Ё':
                                shift = 6
                            else:
                                shift = ord(key_char) - ord('А')
                                if shift >= 6:
                                    shift -= 1
                        else:
                            if key_char == 'ё':
                                shift = 6
                            else:
                                shift = ord(key_char) - ord('а')
                                if shift >= 6:
                                    shift -= 1
                    else:
                        shift = 3
                    
                    if not encrypt:
                        shift = -shift
                    
                    new_pos = (pos + shift) % 32
                    if new_pos >= 6:
                        new_pos += 1
                    result += chr(start + new_pos)
                    keyword_index += 1
                else:
                    start = ord('а')
                    pos = ord(char) - start
                    if pos >= 6:
                        pos -= 1
                    
                    key_char = keyword[keyword_index % len(keyword)]
                    key_lang = detect_alphabet(key_char)
                    
                    if key_lang == 'ru':
                        if key_char.isupper():
                            if key_char == 'Ё':
                                shift = 6
                            else:
                                shift = ord(key_char) - ord('А')
                                if shift >= 6:
                                    shift -= 1
                        else:
                            if key_char == 'ё':
                                shift = 6
                            else:
                                shift = ord(key_char) - ord('а')
                                if shift >= 6:
                                    shift -= 1
                    else:
                        shift = 3
                    
                    if not encrypt:
                        shift = -shift
                    
                    new_pos = (pos + shift) % 32
                    if new_pos >= 6:
                        new_pos += 1
                    result += chr(start + new_pos)
                    keyword_index += 1
        
        else:
            # Не буква - оставляем как есть
            result += char
    
    return result

# ============= МАРШРУТЫ ДЛЯ ШИФРОВАНИЯ И РАСШИФРОВКИ =============

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        text = request.form['text']
        password = request.form.get('password', '')
        cipher_type = request.form['cipher_type']
        
        if cipher_type == 'fernet':
            # Современное шифрование (Fernet) - работает с любым текстом
            key = Fernet.generate_key()
            f = Fernet(key)
            encrypted = f.encrypt(text.encode())
            
            result = {
                'encrypted': encrypted.decode(),
                'key': key.decode(),
                'note': 'Сохраните этот ключ! Он понадобится для расшифровки.'
            }
        elif cipher_type == 'caesar':
            # Шифр Цезаря
            shift = int(request.form.get('shift', 3))
            encrypted = caesar_cipher(text, shift)
            result = {
                'encrypted': encrypted,
                'key': f'Сдвиг: {shift}',
                'note': 'Поддерживаются русский и английский языки. Небуквенные символы сохраняются.'
            }
        elif cipher_type == 'vigenere':
            # Шифр Виженера
            keyword = request.form.get('keyword', 'KEY')
            encrypted = vigenere_cipher(text, keyword, encrypt=True)
            result = {
                'encrypted': encrypted,
                'key': f'Ключевое слово: {keyword}',
                'note': 'Поддерживаются русский и английский языки. Для лучшего результата используйте ключ на том же языке, что и текст.'
            }
        
        # Логируем операцию
        log_operation('encrypt', cipher_type)
        
        return render_template('result.html', result=result, action='encrypt')
    
    return render_template('encrypt.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        encrypted_text = request.form['encrypted_text']
        key_input = request.form['key']
        cipher_type = request.form['cipher_type']
        
        try:
            if cipher_type == 'fernet':
                # Расшифровка Fernet
                f = Fernet(key_input.encode())
                decrypted = f.decrypt(encrypted_text.encode())
                result = decrypted.decode()
            elif cipher_type == 'caesar':
                # Расшифровка Цезаря
                shift = int(key_input.split(':')[1].strip())
                result = caesar_cipher(encrypted_text, -shift)
            elif cipher_type == 'vigenere':
                # Расшифровка Виженера
                keyword = key_input.split(':')[1].strip()
                result = vigenere_cipher(encrypted_text, keyword, encrypt=False)
            
            log_operation('decrypt', cipher_type)
            
            return render_template('result.html', 
                                 result={'decrypted': result}, 
                                 action='decrypt')
        except Exception as e:
            print(f"Ошибка расшифровки: {e}")
            return render_template('decrypt.html', 
                                 error='Ошибка расшифровки. Проверьте ключ и данные.')
    
    return render_template('decrypt.html')

# Логирование операций
def log_operation(op_type, cipher_type):
    try:
        conn = sqlite3.connect('cipher_history.db')
        c = conn.cursor()
        c.execute('INSERT INTO operations (operation_type, cipher_type, timestamp) VALUES (?, ?, ?)',
                  (op_type, cipher_type, datetime.now().isoformat()))
        conn.commit()
        conn.close()
    except:
        pass

# API для получения статистики
@app.route('/api/stats')
def get_stats():
    try:
        conn = sqlite3.connect('cipher_history.db')
        c = conn.cursor()
        c.execute('SELECT cipher_type, COUNT(*) FROM operations GROUP BY cipher_type')
        stats = dict(c.fetchall())
        conn.close()
        return jsonify(stats)
    except:
        return jsonify({})

if __name__ == '__main__':
    app.run(debug=True)
