from flask import Flask, request, render_template, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import json
import os

app = Flask(__name__)

# AES 加密密钥（必须是 16、24 或 32 字节）
SECRET_KEY = b'xAI_Grok3_2025_16bytes_key123456'  # 32 字节密钥
IV = b'1234567890abcdef'  # 初始化向量，16 字节

# 模拟数据
MOCK_DATA = {
    "id": 1,
    "name": "Test User",
    "email": "test@example.com",
    "status": "active"
}

# AES 加密函数
def encrypt_data(data, key=SECRET_KEY, iv=IV):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data.encode(), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted_data).decode('utf-8')

# AES 解密函数
def decrypt_data(encrypted_data, key=SECRET_KEY, iv=IV):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_bytes = base64.b64decode(encrypted_data)
    decrypted_padded = cipher.decrypt(encrypted_bytes)
    return unpad(decrypted_padded, AES.block_size).decode('utf-8')

# 前端页面路由
@app.route('/')
def index():
    return render_template('index.html')

# 查询数据接口
@app.route('/query', methods=['POST'])
def query_data():
    try:
        # 获取加密的请求体
        encrypted_body = request.data.decode('utf-8')
        # 解密请求体
        decrypted_body = decrypt_data(encrypted_body)
        # 解析 JSON
        request_json = json.loads(decrypted_body)
        
        # 获取加密的参数并解密
        encrypted_param = request_json.get('data')
        decrypted_param = decrypt_data(encrypted_param)
        param_json = json.loads(decrypted_param)
        
        # 模拟查询逻辑（这里直接返回 mock 数据）
        response_data = MOCK_DATA
        
        # 将响应数据转为 JSON 并加密
        response_json = json.dumps(response_data)
        encrypted_response = encrypt_data(response_json)
        
        # 对整个响应体再次加密
        response_body = json.dumps({"data": encrypted_response})
        encrypted_body = encrypt_data(response_body)
        
        return encrypted_body
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)
