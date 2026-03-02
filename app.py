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

# Функция для генерации ключа из пароля (key derivation)
def generate_key_from_password(password: str, salt: bytes = None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

# Главная страница с историей шифров
@app.route('/')
def index():
    return render_template('index.html')

# Страница "О проекте" - ИСПРАВЛЕНО: добавлен этот маршрут
@app.route('/about')
def about():
    return render_template('about.html')

# Страница шифрования
@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        text = request.form['text']
        password = request.form.get('password', '')
        cipher_type = request.form['cipher_type']
        
        if cipher_type == 'fernet':
            # Современное шифрование (Fernet)
            key = Fernet.generate_key()
            f = Fernet(key)
            encrypted = f.encrypt(text.encode())
            
            # Сохраняем ключ в сессии для последующей расшифровки
            session['last_key'] = key.decode()
            session['last_salt'] = None
            
            result = {
                'encrypted': encrypted.decode(),
                'key': key.decode(),
                'note': 'Сохраните этот ключ! Он понадобится для расшифровки.'
            }
        elif cipher_type == 'caesar':
            # Шифр Цезаря (для образовательных целей)
            shift = int(request.form.get('shift', 3))
            encrypted = caesar_cipher(text, shift)
            result = {
                'encrypted': encrypted,
                'key': f'Сдвиг: {shift}',
                'note': 'Классический шифр Цезаря. Для расшифровки используйте тот же сдвиг.'
            }
        elif cipher_type == 'vigenere':
            # Шифр Виженера
            keyword = request.form.get('keyword', 'KEY')
            encrypted = vigenere_cipher(text, keyword, encrypt=True)
            result = {
                'encrypted': encrypted,
                'key': f'Ключевое слово: {keyword}',
                'note': 'Шифр Виженера — первый полиалфавитный шифр.'
            }
        
        # Логируем операцию
        log_operation('encrypt', cipher_type)
        
        return render_template('result.html', result=result, action='encrypt')
    
    return render_template('encrypt.html')

# Страница расшифровки
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
                # Извлекаем число из строки "Сдвиг: 3"
                shift = int(key_input.split(':')[1].strip())
                result = caesar_cipher(encrypted_text, -shift)
            elif cipher_type == 'vigenere':
                # Расшифровка Виженера
                # Извлекаем ключевое слово из строки "Ключевое слово: KEY"
                keyword = key_input.split(':')[1].strip()
                result = vigenere_cipher(encrypted_text, keyword, encrypt=False)
            
            log_operation('decrypt', cipher_type)
            
            return render_template('result.html', 
                                 result={'decrypted': result}, 
                                 action='decrypt')
        except Exception as e:
            print(f"Ошибка расшифровки: {e}")  # Для отладки
            return render_template('decrypt.html', 
                                 error='Ошибка расшифровки. Проверьте ключ и данные.')
    
    return render_template('decrypt.html')

# Шифр Цезаря
def caesar_cipher(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char
    return result

# Шифр Виженера
def vigenere_cipher(text, keyword, encrypt=True):
    result = ""
    keyword = keyword.upper()
    keyword_index = 0
    
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            keyword_char = keyword[keyword_index % len(keyword)]
            shift = ord(keyword_char) - 65
            
            if not encrypt:
                shift = -shift
                
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            keyword_index += 1
        else:
            result += char
    
    return result

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
        pass  # Игнорируем ошибки базы данных

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