# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import json
import os
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import time
import mymessage_pb2
import threading

app = Flask(__name__)

UIDS_FILE = "uids.json"
TOKEN_CACHE_FILE = "token_cache.json"

# إعدادات ثابتة
ACCOUNT_UID = "4173875842"  # ضع الUID الثابت هنا
ACCOUNT_PASSWORD = "LVL_UP_OHV6FVHT" # ضع الباسوورد الثابت هنا

# إعدادات التشفير
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

# دوال التخزين
def load_uids():
    if not os.path.exists(UIDS_FILE):
        return {}
    try:
        with open(UIDS_FILE, "r", encoding='utf-8') as f:
            return json.load(f)
    except:
        return {}

def save_uids(data):
    with open(UIDS_FILE, "w", encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def load_token_cache():
    if not os.path.exists(TOKEN_CACHE_FILE):
        return {}
    try:
        with open(TOKEN_CACHE_FILE, "r", encoding='utf-8') as f:
            return json.load(f)
    except:
        return {}

def save_token_cache(data):
    with open(TOKEN_CACHE_FILE, "w", encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

# دوال البروتوباف والتشفير
def create_protobuf_message(target_uid):
    message = mymessage_pb2.MyMessage()
    message.field1 = 9797549324
    message.field2 = int(target_uid)
    message.field3 = 22
    return message.SerializeToString()

def encrypt_message(plaintext):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)

def get_request_headers(jwt_token, content_length):
    return {
        'User-Agent': "Dalvik/2.1.0 (Linux; Android 9)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Authorization': f"Bearer {jwt_token}",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB50",
        'Content-Length': str(content_length)
    }

# دالة التوكن الثابتة
def GET_JWT_TOKEN():
    try:
        # المرحلة 1: الحصول على التوكن من Garena
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close"
        }
        
        data = {
            "uid": ACCOUNT_UID,
            "password": ACCOUNT_PASSWORD,
            "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067"
        }
        
        response = requests.post(url, headers=headers, data=data, timeout=30)
        response_data = response.json()

        NEW_ACCESS_TOKEN = response_data['access_token']
        NEW_OPEN_ID = response_data['open_id']
        OLD_ACCESS_TOKEN = "1f164b149a618e3e0c77232d08913765c7b11c3d86ee21bb541e797cd114951d"
        OLD_OPEN_ID = "e32fabfd33fd3e5d0c19547b13727cb9"

        # البيانات الثابتة
        data_hex = '1a13323032342d31322d30352031313a31393a3535220966726565206669726528013a07312e3130382e334242416e64726f6964204f532039202f204150492d32382028505133412e3139303830312e3030322f656e672e666f6c6c6f772e32303139303931362e313630393036294a0848616e6468656c645a045749464960b60a68c10672033234307a1d41524d3634204650204153494d4420414553207c2031363930207c203880019c0e8a01094d616c692d5438333092013e4f70656e474c20455320332e322076312e72323270302d303172656c302e6232616163353133316361653639643761303432356464353162386639626364a2010c34352e3234332e31302e3632aa0102656eb201206533326661626664333366643365356430633139353437623133373237636239ba010134c2010848616e6468656c64ca010f73616d73756e6720534d2d54353835ea014031663136346231343961363138653365306337373233326430383931333736356337623131633364383665653231626235343165373937636431313439353164f00101d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e00395c601e803e218f003c316f803c4088004e218880495c6019004e218980495c601c80401d2043f2f646174612f6170702f636f6d2e6474732e667265656669726574682d336f4669564137526f31634a423858795339503352413d3d2f6c69622f61726d3634e00401ea045f35623839326161616264363838653537316636383830353331313861313632627c2f646174612f6170702f636f6d2e6474732e667265656669726574682d336f4669564137526f31634a423858795339503352413d3d2f626173652e61706bf00403f804028a050236349a050a32303139313137383633b205094f70656e474c455332b805ff7fc00504ca050940004c17535b0f5130e005e0c701ea0507616e64726f6964f2055c4b71734854367033557276565042647073486772496573456b63424255794a6f4d544b6d4e315445646542794b722b454e376d6b2b3550476e483171376448365767586564324e343350744c4152372b6472377734396b4a5a77413df8058de4068806019006019a060134a2060134'
        
        data_bytes = bytes.fromhex(data_hex)
        data_bytes = data_bytes.replace(OLD_OPEN_ID.encode(), NEW_OPEN_ID.encode())
        data_bytes = data_bytes.replace(OLD_ACCESS_TOKEN.encode(), NEW_ACCESS_TOKEN.encode())
        
        # تشفير البيانات
        encrypted_data = encrypt_message(data_bytes)

        # المرحلة 2: الحصول على JWT النهائي
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB50',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ.eyJhY2NvdW50X2lkIjo5MjgwODkyMDE4LCJuaWNrbmFtZSI6IkJZVEV2R3QwIiwibm90aV9yZWdpb24iOiJNRSIsImxvY2tfcmVnaW9uIjoiTUUiLCJleHRlcm5hbF9pZCI6ImYzNGQyMjg0ZWJkYmFkNTkzNWJjOGI1NTZjMjY0ZmMwIiwiZXh0ZXJuYWxfdHlwZSI6NCwicGxhdF9pZCI6MCwiY2xpZW50X3ZlcnNpb24iOiIxLjEwNS41IiwiZW11bGF0b3Jfc2NvcmUiOjAsImlzX2VtdWxhdG9yIjpmYWxzZSwiY291bnRyeV9jb2ReIjoiRUciLCJleHRlcm5hbF91aWQiOjMyMzQ1NDE1OTEsInJlZ19hdmF0YXIiOjEwMjAwMDAwNSwic291cmNlIjoyLCJsb2NrX3JlZ2lvbl90aW1lIjoxNzE0NjYyMzcyLCJjbGllbnRfdHlwZSI6MSwic2lnbmF0dXJlX21kNSI6IiIsInVzaW5nX3ZlcnNpb24iOjEsInJlbGVhc2VfY2hhbm5lbCI6ImlvcyIsInJlbGVhc2VfdmVyc2lvbiI6Ik9CNDUiLCJleHAiOjE3MjIwNTkxMjF9.yYQZX0GeBMeBtMLhyCjSV0Q3e0jAqhnMZd3XOs6Ldk4',
            'Content-Length': str(len(encrypted_data)),
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.common.ggbluefox.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }

        URL = "https://loginbp.common.ggbluefox.com/MajorLogin"
        response = requests.post(URL, headers=headers, data=encrypted_data, verify=False, timeout=30)

        if response.status_code == 200 and len(response.text) >= 10:
            response_text = response.text
            start_index = response_text.find("eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ")
            if start_index != -1:
                jwt_token = response_text[start_index:]
                second_dot_index = jwt_token.find(".", jwt_token.find(".") + 1)
                if second_dot_index != -1:
                    jwt_token = jwt_token[:second_dot_index + 44]
                    return jwt_token
        return None
    except Exception as e:
        print(f"Error generating JWT token: {e}")
        return None

def get_cached_jwt_token():
    """الحصول على JWT من الكاش أو توليد جديد"""
    token_cache = load_token_cache()
    now = datetime.now().timestamp()
    
    cache_key = f"{ACCOUNT_UID}_{ACCOUNT_PASSWORD}"
    
    if cache_key in token_cache:
        token_data = token_cache[cache_key]
        # تجديد كل 4 ساعات
        if now - token_data['timestamp'] < 4 * 3600:
            return token_data['token']
    
    # توليد توكن جديد
    new_token = GET_JWT_TOKEN()
    if new_token:
        token_cache[cache_key] = {
            'token': new_token,
            'timestamp': now
        }
        save_token_cache(token_cache)
        return new_token
    
    return None

def send_api_request(target_uid, api_url, max_retries=3):
    """إرسال طلب API مع JWT تلقائي"""
    # الحصول على JWT من الكاش
    jwt_token = get_cached_jwt_token()
    if not jwt_token:
        return None, "فشل في الحصول على JWT token"
    
    # إنشاء البروتوباف
    protobuf_msg = create_protobuf_message(target_uid)
    encrypted_data = encrypt_message(protobuf_msg)
    headers = get_request_headers(jwt_token, len(encrypted_data))

    for attempt in range(max_retries):
        try:
            response = requests.post(api_url, data=encrypted_data, headers=headers, verify=False, timeout=15)
            return response, None
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                time.sleep(2)

    return None, "فشلت جميع محاولات الإرسال"

def cleanup_expired_uids():
    """حذف الUIDs المنتهية الصلاحية"""
    while True:
        try:
            data = load_uids()
            now = datetime.now().timestamp()
            expired_count = 0
            
            uids_to_delete = []
            for uid, info in data.items():
                expire_time = info.get('expire')
                if expire_time and now > expire_time:
                    uids_to_delete.append(uid)
                    expired_count += 1
            
            # حذف المنتهية
            for uid in uids_to_delete:
                del data[uid]
            
            if uids_to_delete:
                save_uids(data)
                print(f"🗑️ تم حذف {expired_count} UID منتهي الصلاحية")
            
            # الانتظار 5 دقائق بين كل فحص
            time.sleep(300)
            
        except Exception as e:
            print(f"Error in cleanup: {e}")
            time.sleep(300)

# بدء خدمة التنظيف التلقائي
cleanup_thread = threading.Thread(target=cleanup_expired_uids, daemon=True)
cleanup_thread.start()

# ========== Routes ==========
@app.route('/check_uid', methods=['GET'])
def check_uid():
    uid = request.args.get("id")
    if not uid:
        return jsonify({"error": "Missing id parameter"}), 400
    
    try:
        data = load_uids()
        user_data = data.get(uid)
        
        if not user_data:
            return jsonify({"status": "not_found", "expire": None}), 404
        
        status = user_data.get("status", "unknown")
        expire = user_data.get("expire")
        
        if not expire:
            return jsonify({
                "status": status,
                "expire": None,
                "remaining": "No expire date"
            })
        
        now = datetime.now()
        expire_date = datetime.fromtimestamp(expire)
        remaining_time = expire_date - now
        
        if remaining_time.total_seconds() <= 0:
            # حذف إذا انتهى الوقت
            del data[uid]
            save_uids(data)
            return jsonify({
                "status": "expired",
                "expire": expire,
                "remaining": "Expired (Auto Deleted)"
            })
        
        hours = int(remaining_time.total_seconds() // 3600)
        minutes = int((remaining_time.total_seconds() % 3600) // 60)
        seconds = int(remaining_time.total_seconds() % 60)
        
        formatted_time = f"{hours} Hour - {minutes} Min - {seconds} Sec"
        
        return jsonify({
            "status": status,
            "expire": expire,
            "remaining": formatted_time,
            "added_at": user_data.get("added_at"),
            "added_by": user_data.get("added_by")
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/add', methods=['GET'])
def add_friend():
    target_uid = request.args.get('id')
    hours = request.args.get('hours', default=24, type=int)  # الوقت بالساعات
    
    if not target_uid:
        return jsonify({"error": "يجب توفير id"}), 400
    
    if hours <= 0:
        return jsonify({"error": "الوقت يجب أن يكون أكبر من 0"}), 400

    # إرسال طلب الإضافة
    response, error = send_api_request(
        target_uid, 
        "https://clientbp.ggblueshark.com/RequestAddingFriend"
    )

    if error:
        return jsonify({"error": error}), 500

    # حفظ في قاعدة البيانات مع الوقت المحدد
    data = load_uids()
    expire_time = (datetime.now() + timedelta(hours=hours)).timestamp()
    
    data[target_uid] = {
        "status": "active",
        "expire": expire_time,
        "added_at": datetime.now().isoformat(),
        "added_by": ACCOUNT_UID,
        "last_updated": datetime.now().isoformat(),
        "hours": hours
    }
    save_uids(data)

    return jsonify({
        "status": response.status_code, 
        "response": response.text,
        "message": f"تمت الإضافة بنجاح لمدة {hours} ساعة",
        "expire_time": datetime.fromtimestamp(expire_time).isoformat()
    }), response.status_code

@app.route('/remove', methods=['GET'])
def remove_friend():
    target_uid = request.args.get('id')
    
    if not target_uid:
        return jsonify({"error": "يجب توفير id"}), 400

    # إرسال طلب الإزالة
    response, error = send_api_request(
        target_uid,
        "https://clientbp.common.ggbluefox.com/RemoveFriend"
    )

    if error:
        return jsonify({"error": error}), 500

    # حذف فوري من قاعدة البيانات
    data = load_uids()
    if target_uid in data:
        del data[target_uid]
        save_uids(data)
        message = "تمت الإزالة بنجاح وحذف من قاعدة البيانات"
    else:
        message = "تمت الإزالة بنجاح (لم يكن موجوداً في قاعدة البيانات)"

    return jsonify({
        "status": response.status_code, 
        "response": response.text,
        "message": message
    }), response.status_code

@app.route('/list', methods=['GET'])
def list_uids():
    data = load_uids()
    
    # إضافة معلومات الوقت المتبقي
    now = datetime.now().timestamp()
    for uid, info in data.items():
        expire_time = info.get('expire')
        if expire_time:
            remaining = expire_time - now
            if remaining <= 0:
                info['remaining'] = "منتهي"
                info['status'] = "expired"
            else:
                hours = int(remaining // 3600)
                minutes = int((remaining % 3600) // 60)
                info['remaining'] = f"{hours}h {minutes}m"
        else:
            info['remaining'] = "لا يوجد وقت"
    
    return jsonify({"total": len(data), "uids": data})

@app.route('/delete', methods=['GET'])
def delete_uid():
    uid = request.args.get('id')
    if not uid:
        return jsonify({"error": "يجب توفير id"}), 400
    
    data = load_uids()
    if uid in data:
        del data[uid]
        save_uids(data)
        return jsonify({"message": f"تم حذف UID {uid}"})
    else:
        return jsonify({"error": "UID غير موجود"}), 404

@app.route('/cleanup', methods=['GET'])
def manual_cleanup():
    """تنظيف يدوي للUIDs المنتهية"""
    data = load_uids()
    now = datetime.now().timestamp()
    expired_count = 0
    
    uids_to_delete = []
    for uid, info in data.items():
        expire_time = info.get('expire')
        if expire_time and now > expire_time:
            uids_to_delete.append(uid)
            expired_count += 1
    
    for uid in uids_to_delete:
        del data[uid]
    
    if uids_to_delete:
        save_uids(data)
        return jsonify({"message": f"تم حذف {expired_count} UID منتهي"})
    else:
        return jsonify({"message": "لا توجد UIDs منتهية"})

@app.route('/token', methods=['GET'])
def get_token_status():
    """فحص حالة التوكن"""
    token = get_cached_jwt_token()
    if token:
        return jsonify({"status": "active", "token": token[:50] + "..."})
    else:
        return jsonify({"status": "inactive", "token": None})

if __name__ == '__main__':
    # إنشاء الملفات إذا لم تكن موجودة
    if not os.path.exists(UIDS_FILE):
        save_uids({})
    if not os.path.exists(TOKEN_CACHE_FILE):
        save_token_cache({})
    
    print(f"✅ السيرفر شغال على port 5000")
    print(f"📱 Account UID: {ACCOUNT_UID}")
    print("🕐 خدمة التنظيف التلقائي شغالة (كل 5 دقائق)")
    print("\n🌐 روابط الاستخدام:")
    print(f"➕ إضافة: http://localhost:5000/add?id=123456&hours=24")
    print(f"➖ إزالة: http://localhost:5000/remove?id=123456")
    print(f"🔍 فحص: http://localhost:5000/check_uid?id=123456")
    print(f"📋 القائمة: http://localhost:5000/list")
    print(f"🗑️ حذف: http://localhost:5000/delete?id=123456")
    print(f"🧹 تنظيف: http://localhost:5000/cleanup")
    print(f"🔐 حالة التوكن: http://localhost:5000/token")
    
    app.run(host='0.0.0.0', port=5000, debug=True)