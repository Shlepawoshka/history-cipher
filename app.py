from flask import Flask, render_template, request, jsonify, session
from cryptography.fernet import Fernet
import base64
import os
import sqlite3
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.urandom(24)

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

# ============= РУССКИЙ И АНГЛИЙСКИЙ АЛФАВИТЫ =============

# Русский алфавит (33 буквы с Ё)
RUS_UPPER = 'АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ'
RUS_LOWER = 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя'

# Английский алфавит
ENG_UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
ENG_LOWER = 'abcdefghijklmnopqrstuvwxyz'

def is_russian(char):
    """Проверяет, является ли символ русской буквой"""
    return char in RUS_UPPER or char in RUS_LOWER

def is_english(char):
    """Проверяет, является ли символ английской буквой"""
    return char in ENG_UPPER or char in ENG_LOWER

def caesar_cipher(text, shift):
    """
    Шифр Цезаря с поддержкой русского и английского языков
    shift может быть положительным (шифрование) или отрицательным (расшифровка)
    """
    result = ""
    
    for char in text:
        if is_russian(char):
            # Русский алфавит
            if char in RUS_UPPER:
                idx = RUS_UPPER.index(char)
                new_idx = (idx + shift) % 33
                result += RUS_UPPER[new_idx]
            else:  # нижний регистр
                idx = RUS_LOWER.index(char)
                new_idx = (idx + shift) % 33
                result += RUS_LOWER[new_idx]
        
        elif is_english(char):
            # Английский алфавит
            if char in ENG_UPPER:
                idx = ENG_UPPER.index(char)
                new_idx = (idx + shift) % 26
                result += ENG_UPPER[new_idx]
            else:  # нижний регистр
                idx = ENG_LOWER.index(char)
                new_idx = (idx + shift) % 26
                result += ENG_LOWER[new_idx]
        
        else:
            # Не буква (цифры, знаки препинания) - оставляем как есть
            result += char
    
    return result

def vigenere_cipher(text, keyword, encrypt=True):
    """
    Шифр Виженера с поддержкой русского и английского языков
    """
    result = ""
    keyword_index = 0
    
    # Приводим ключевое слово к верхнему регистру для простоты
    keyword_upper = keyword.upper()
    
    for char in text:
        if is_russian(char):
            # Работаем с русским текстом
            is_upper = char in RUS_UPPER
            alphabet = RUS_UPPER if is_upper else RUS_LOWER
            idx = alphabet.index(char)
            
            # Получаем сдвиг из ключевого слова
            key_char = keyword_upper[keyword_index % len(keyword_upper)]
            
            # Определяем, на каком языке ключевой символ
            if key_char in RUS_UPPER:
                # Ключ на русском
                shift = RUS_UPPER.index(key_char)
            else:
                # Если ключ на английском или другом, преобразуем в число
                # Просто используем позицию в английском алфавите
                shift = ENG_UPPER.index(key_char) if key_char in ENG_UPPER else 3
            
            if not encrypt:
                shift = -shift
            
            new_idx = (idx + shift) % 33
            result += alphabet[new_idx]
            keyword_index += 1
        
        elif is_english(char):
            # Работаем с английским текстом
            is_upper = char in ENG_UPPER
            alphabet = ENG_UPPER if is_upper else ENG_LOWER
            idx = alphabet.index(char)
            
            # Получаем сдвиг из ключевого слова
            key_char = keyword_upper[keyword_index % len(keyword_upper)]
            
            # Определяем сдвиг (пытаемся использовать русский или английский)
            if key_char in RUS_UPPER:
                shift = RUS_UPPER.index(key_char) % 26
            else:
                shift = ENG_UPPER.index(key_char) if key_char in ENG_UPPER else 3
            
            if not encrypt:
                shift = -shift
            
            new_idx = (idx + shift) % 26
            result += alphabet[new_idx]
            keyword_index += 1
        
        else:
            # Не буква - оставляем как есть
            result += char
    
    return result

# ============= МАРШРУТЫ =============

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        text = request.form['text']
        cipher_type = request.form['cipher_type']
        
        if cipher_type == 'fernet':
            # Fernet работает с байтами, поэтому поддерживает любые языки
            key = Fernet.generate_key()
            f = Fernet(key)
            encrypted = f.encrypt(text.encode('utf-8'))
            
            result = {
                'encrypted': encrypted.decode('utf-8'),
                'key': key.decode('utf-8'),
                'note': 'Сохраните этот ключ! Он понадобится для расшифровки.'
            }
        elif cipher_type == 'caesar':
            shift = int(request.form.get('shift', 3))
            encrypted = caesar_cipher(text, shift)
            result = {
                'encrypted': encrypted,
                'key': f'Сдвиг: {shift}',
                'note': 'Поддерживаются русский и английский языки.'
            }
        elif cipher_type == 'vigenere':
            keyword = request.form.get('keyword', 'КЛЮЧ')
            encrypted = vigenere_cipher(text, keyword, encrypt=True)
            result = {
                'encrypted': encrypted,
                'key': f'Ключевое слово: {keyword}',
                'note': 'Поддерживаются русский и английский языки.'
            }
        
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
                key = key_input.encode('utf-8')
                f = Fernet(key)
                decrypted = f.decrypt(encrypted_text.encode('utf-8'))
                result = decrypted.decode('utf-8')
            
            elif cipher_type == 'caesar':
                # Извлекаем число сдвига из строки "Сдвиг: 3"
                if ':' in key_input:
                    shift_str = key_input.split(':')[1].strip()
                else:
                    shift_str = key_input.strip()
                
                shift = int(shift_str)
                # Для расшифровки используем отрицательный сдвиг
                result = caesar_cipher(encrypted_text, -shift)
            
            elif cipher_type == 'vigenere':
                # Извлекаем ключевое слово из строки "Ключевое слово: KEY"
                if ':' in key_input:
                    keyword = key_input.split(':')[1].strip()
                else:
                    keyword = key_input.strip()
                
                result = vigenere_cipher(encrypted_text, keyword, encrypt=False)
            
            log_operation('decrypt', cipher_type)
            return render_template('result.html', 
                                 result={'decrypted': result}, 
                                 action='decrypt')
        
        except Exception as e:
            print(f"Ошибка: {e}")
            error_msg = 'Ошибка расшифровки. Проверьте: <br>1. Правильно ли вы скопировали ключ<br>2. Совпадает ли метод шифрования<br>3. Не был ли изменен текст'
            return render_template('decrypt.html', error=error_msg)
    
    return render_template('decrypt.html')

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

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
