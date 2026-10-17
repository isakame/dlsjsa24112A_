from flask import Flask, send_file, request
import os
import logging
import re
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ==================== НАСТРОЙКИ ====================
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
PAYLOAD_FILE = 'payload.bin'
STATIC_KEY_PART = "s0Rzj5P2"
# Удаляем FIXED_KEY, теперь он будет динамическим

# ==================== ДАННЫЕ ====================
RESPONSE_UPDATE = "s;15806e558d99ab43afd65db8637a16528aaba8e3a766f1a006fbc0451b06a9c9"
RESPONSE_LOAD = "s;15806e558d99ab43afd65db8637a1652fd4c2e3b3a5641e871509a61846da4f3b20d5b2c0a90a7c20f2f988f0c48aaf6"
SUBSCRIPTION_DATA = "n;1;FollowBot;1;Undetected;1;2023-04-02 22:29:32;0;3;1;n;2;External Overlay;1;Undetected;1;2024-02-13 05:18:11;0;3;1;n;3;AutoBot"

encrypted_cache = None
encrypted_uptime_cache = None

# ==================== ШИФРОВАНИЕ / ДЕШИФРОВАНИЕ ====================
def aes128_ecb_encrypt(plaintext: str, key: str) -> bytes:
    key_bytes = key.encode('utf-8')[:16].ljust(16, b'\0')
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
    return cipher.encrypt(padded_data)

def aes128_ecb_decrypt(ciphertext_hex: str, key: str) -> str:
    key_bytes = key.encode('utf-8')[:16].ljust(16, b'\0')
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    ciphertext = bytes.fromhex(ciphertext_hex)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted.decode('utf-8')

def decrypt_d_param(encrypted_d: str, e_param: str) -> str:
    """Расшифровывает параметр d используя полный ключ (e + статическая часть)"""
    full_key = (e_param + STATIC_KEY_PART)[:16]
    try:
        decrypted = aes128_ecb_decrypt(encrypted_d, full_key)
        logger.info(f"🔓 Decrypted d: {decrypted[:100]}...")
        return decrypted
    except Exception as e:
        logger.error(f"❌ Failed to decrypt d: {e}")
        return ""

def extract_params_from_decrypted(decrypted_text: str) -> dict:
    """Извлекает параметры ct, hw и hash из расшифрованного текста"""
    params = {
        'ct': '',
        'hw': '8a07280d001E39491DD9',  # значение по умолчанию
        'hash': '15839555f7729ab888e635fc14182de5'  # значение по умолчанию
    }
    
    # Извлекаем ct
    ct_match = re.search(r';&ct=(\d+);', decrypted_text)
    if ct_match:
        params['ct'] = ct_match.group(1)
        logger.info(f"📊 Extracted ct: {params['ct']}")
    
    # Извлекаем hw (ищем после ;hw= или ;&hw=)
    hw_match = re.search(r'[;&]hw=([^;]+)', decrypted_text)
    if hw_match:
        params['hw'] = hw_match.group(1)
        logger.info(f"📊 Extracted hw: {params['hw']}")
    else:
        logger.warning("⚠️ hw not found in decrypted text, using default")
    
    # Извлекаем hash (ищем после ;hash= или ;&hash=)
    hash_match = re.search(r'[;&]hash=([^;]+)', decrypted_text)
    if hash_match:
        params['hash'] = hash_match.group(1)
        logger.info(f"📊 Extracted hash: {params['hash']}")
    else:
        logger.warning("⚠️ hash not found in decrypted text, using default")
    
    return params

def build_dynamic_key(hash_value: str) -> str:
    """
    Строит динамический ключ в формате:
    8327447261105462922{&hash}3w09jg405sdrign
    """
    # Базовая часть ключа (первые 19 цифр)
    base_key = "8327447261105462922"
    # Добавляем hash значение
    dynamic_key = f"{base_key}{hash_value}3w09jg405sdrign"
    logger.info(f"🔑 Dynamic key built: {dynamic_key[:30]}...")
    return dynamic_key

def build_uptime_plaintext(params: dict, e_param: str, dynamic_key: str) -> str:
    """Строит динамический plaintext для шифрования с извлеченными параметрами"""
    combined = e_param + "-" + dynamic_key
    md5_hash = hashlib.md5(combined.encode('utf-8')).hexdigest()
    logger.info(f"🔐 Combined: {combined[:50]}...")
    logger.info(f"🔐 MD5 hash: {md5_hash}")
    
    if params['ct']:
        try:
            new_ct = int(params['ct']) + 586
            logger.info(f"🔄 Updated ct: {params['ct']} -> {new_ct}")
            ct_value = str(new_ct)
        except ValueError:
            logger.error(f"❌ Invalid ct value: {params['ct']}")
            ct_value = "87124431"
    else:
        logger.warning("⚠️ Using default ct")
        ct_value = "87124431"
    
    random_value = random.randint(100000, 999999)
    
    plaintext = f"s;-8327447261105462922;{params['hash']};{params['hw']};0;{md5_hash};{ct_value};{random_value};0982340980546234"
    logger.info(f"📝 New plaintext built with hw={params['hw']} and hash={params['hash']} | random={random_value}")
    return plaintext

def compute_md5_hash(e_param: str, dynamic_key: str) -> str:
    """Вычисляет MD5 хеш с дефисом как разделителем"""
    combined = e_param + "-" + dynamic_key
    return hashlib.md5(combined.encode('utf-8')).hexdigest()

# ==================== МАРШРУТЫ ====================
@app.route('/subscription', methods=['GET'])
def subscription():
    global encrypted_cache
    key = request.args.get('key')
    
    if key:
        logger.info(f"🔑 Encrypting with key: {key}")
        full_key = (key + STATIC_KEY_PART)[:16]
        encrypted = aes128_ecb_encrypt(SUBSCRIPTION_DATA, full_key)
        encrypted_cache = encrypted.hex()
        logger.info("✅ Encrypted subscription ready")
    
    if encrypted_cache is None:
        return 'Service Unavailable', 503
    
    return f"s;6;{encrypted_cache}", 200, {'Content-Type': 'text/plain'}

@app.route('/update', methods=['GET'])
def update():
    return RESPONSE_UPDATE, 200, {'Content-Type': 'text/plain'}

@app.route('/load', methods=['GET'])
def load():
    return RESPONSE_LOAD, 200, {'Content-Type': 'text/plain'}
    
@app.route('/uptime', methods=['GET'])
def uptime():
    global encrypted_uptime_cache
    
    key = request.args.get('key')      # e= параметр
    d_param = request.args.get('d')    # d= параметр
    
    if key:
        logger.info(f"🔑 Received key (e): {key}")
        
        if d_param:
            logger.info(f"🔐 Received d parameter, decrypting...")
            
            decrypted_d = decrypt_d_param(d_param, key)
            
            if decrypted_d:
                params = extract_params_from_decrypted(decrypted_d)
                dynamic_key = build_dynamic_key(params['hash'])
                plaintext = build_uptime_plaintext(params, key, dynamic_key)
            else:
                logger.warning("⚠️ Using default plaintext with default hash")
                default_hash = "15839555f7729ab888e635fc14182de5"
                dynamic_key = build_dynamic_key(default_hash)
                md5_hash = compute_md5_hash(key, dynamic_key)
                random_value = random.randint(100000, 999999)
                plaintext = f"s;-8327447261105462922;{default_hash};8a07280d001E39491DD9;0;{md5_hash};87124431;{random_value};0982340980546234"
        else:
            logger.info("ℹ️ No d parameter, using default plaintext")
            default_hash = "15839555f7729ab888e635fc14182de5"
            dynamic_key = build_dynamic_key(default_hash)
            md5_hash = compute_md5_hash(key, dynamic_key)
            random_value = random.randint(100000, 999999)
            plaintext = f"s;-8327447261105462922;{default_hash};8a07280d001E39491DD9;0;{md5_hash};87124431;{random_value};0982340980546234"
        
        full_key = (key + STATIC_KEY_PART)[:16]
        encrypted = aes128_ecb_encrypt(plaintext, full_key)
        encrypted_uptime_cache = encrypted.hex()
        logger.info("✅ Encrypted uptime ready")
    
    if encrypted_uptime_cache is None:
        return 'Service Unavailable', 503
    
    return f"s;{encrypted_uptime_cache}", 200, {'Content-Type': 'text/plain'}

@app.route('/binary', methods=['GET'])
def binary():
    return serve_payload()

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_file(path):
    return serve_payload()

def serve_payload():
    if not os.path.exists(PAYLOAD_FILE):
        return 'File not found', 404
    
    response = send_file(
        PAYLOAD_FILE,
        as_attachment=True,
        download_name='poefollowbot.zip',
        mimetype='application/zip'
    )
    response.headers['Content-Disposition'] = 'attachment; filename="poefollowbot.zip"'
    return response

# Для локального запуска (если нужно)
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
