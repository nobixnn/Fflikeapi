from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
from pymongo import MongoClient
from datetime import datetime
from bson.objectid import ObjectId

app = Flask(__name__)

# MongoDB configuration
MONGO_URI = "mongodb+srv://adsa31224:CpWXk46In6gRbgFE@akiru.uelgrso.mongodb.net/?retryWrites=true&w=majority"
client = MongoClient(MONGO_URI, connectTimeoutMS=30000, socketTimeoutMS=30000)
db = client['akiru_api']
keys_collection = db['api_keys']

# Create index for faster key lookups
keys_collection.create_index("key", unique=True)

# Default key (for backward compatibility)
DEFAULT_KEY = "AKIRU27474"

def validate_key(api_key):
    """Check if API key exists and is valid"""
    if api_key == DEFAULT_KEY:
        return True
    
    key_data = keys_collection.find_one({"key": api_key})
    if not key_data:
        return False
    
    if 'expiry' in key_data and key_data['expiry'] < datetime.utcnow():
        return False
    
    return True

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB49"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    app.logger.error(f"Request failed with status code: {response.status}")
                    return response.status
                return await response.text()
    except Exception as e:
        app.logger.error(f"Exception in send_request: {e}")
        return None

async def fetch_tokens_from_api():
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("https://you-jwt-api.vercel.app/api/tokens") as response:
                if response.status != 200:
                    app.logger.error(f"Failed to fetch tokens from API. Status: {response.status}")
                    return None
                return await response.json()
    except Exception as e:
        app.logger.error(f"Error fetching tokens from API: {e}")
        return None

async def send_multiple_requests(uid, region, url):
    try:
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            app.logger.error("Failed to create protobuf message.")
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            app.logger.error("Encryption failed.")
            return None
        tasks = []
        tokens = await fetch_tokens_from_api()
        if tokens is None:
            app.logger.error("Failed to load tokens.")
            return None
        for i in range(100):
            token = tokens[i % len(tokens)]["token"]
            tasks.append(send_request(encrypted_uid, token, url))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests: {e}")
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

def make_request(encrypt, region, token):
    try:
        if region == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif region in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB49"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False)
        hex_data = response.content.hex()
        binary = bytes.fromhex(hex_data)
        decode = decode_protobuf(binary)
        if decode is None:
            app.logger.error("Protobuf decoding returned None.")
        return decode
    except Exception as e:
        app.logger.error(f"Error in make_request: {e}")
        return None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError as e:
        app.logger.error(f"Error decoding Protobuf data: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Unexpected error during protobuf decoding: {e}")
        return None

@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    region = request.args.get("region", "").upper()
    api_key = request.args.get("key", DEFAULT_KEY)
    
    if not uid or not region:
        return jsonify({"error": "UID and region are required"}), 400
    
    if not validate_key(api_key):
        return jsonify({"error": "Invalid API key"}), 403

    try:
        async def process_request():
            tokens = await fetch_tokens_from_api()
            if tokens is None:
                raise Exception("Failed to load tokens.")
            token = tokens[0]['token']
            encrypted_uid = enc(uid)
            if encrypted_uid is None:
                raise Exception("Encryption of UID failed.")

            # Get player data before executing like operation
            before = make_request(encrypted_uid, region, token)
            if before is None:
                raise Exception("Failed to retrieve initial player info.")
            try:
                jsone = MessageToJson(before)
            except Exception as e:
                raise Exception(f"Error converting 'before' protobuf to JSON: {e}")
            data_before = json.loads(jsone)
            before_like = data_before.get('AccountInfo', {}).get('Likes', 0)
            try:
                before_like = int(before_like)
            except Exception:
                before_like = 0
            app.logger.info(f"Likes before command: {before_like}")

            # Determine the like URL based on region
            if region == "IND":
                url = "https://client.ind.freefiremobile.com/LikeProfile"
            elif region in {"BR", "US", "SAC", "NA"}:
                url = "https://client.us.freefiremobile.com/LikeProfile"
            else:
                url = "https://clientbp.ggblueshark.com/LikeProfile"

            # Send requests asynchronously
            await send_multiple_requests(uid, region, url)

            # Get player data after executing like operation
            after = make_request(encrypted_uid, region, token)
            if after is None:
                raise Exception("Failed to retrieve player info after like requests.")
            try:
                jsone_after = MessageToJson(after)
            except Exception as e:
                raise Exception(f"Error converting 'after' protobuf to JSON: {e}")
            data_after = json.loads(jsone_after)
            after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
            player_uid = int(data_after.get('AccountInfo', {}).get('UID', 0))
            player_name = str(data_after.get('AccountInfo', {}).get('PlayerNickname', ''))
            like_given = after_like - before_like
            status = 1 if like_given != 0 else 2
            result = {
                "LikesGivenByAPI": like_given,
                "LikesafterCommand": after_like,
                "LikesbeforeCommand": before_like,
                "PlayerNickname": player_name,
                "UID": player_uid,
                "status": status
            }
            return result

        result = asyncio.run(process_request())
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/create', methods=['GET'])
def create_key():
    api_key = request.args.get("key")
    expiry_time = request.args.get("time")
    
    if not api_key:
        return jsonify({"error": "Key parameter is required"}), 400
    
    # Check if key already exists
    if keys_collection.find_one({"key": api_key}):
        return jsonify({"error": "Key already exists"}), 400
    
    key_data = {"key": api_key, "created_at": datetime.utcnow()}
    
    if expiry_time:
        try:
            expiry_date = datetime.strptime(expiry_time, "%d/%m/%Y,%H:%M")
            key_data['expiry'] = expiry_date
        except ValueError:
            return jsonify({"error": "Invalid time format. Use DD/MM/YYYY,HH:MM"}), 400
    
    keys_collection.insert_one(key_data)
    return jsonify({"message": "Key created successfully", "key": api_key})

@app.route('/delete', methods=['GET'])
def delete_key():
    api_key = request.args.get("key")
    
    if not api_key:
        return jsonify({"error": "Key parameter is required"}), 400
    
    if api_key == DEFAULT_KEY:
        return jsonify({"error": "Cannot delete default key"}), 400
    
    result = keys_collection.delete_one({"key": api_key})
    
    if result.deleted_count == 0:
        return jsonify({"error": "Key not found"}), 404
    
    return jsonify({"message": "Key deleted successfully"})

@app.route('/check', methods=['GET'])
def check_key():
    api_key = request.args.get("key")
    
    if not api_key:
        return jsonify({"error": "Key parameter is required"}), 400
    
    if api_key == DEFAULT_KEY:
        return jsonify({"key": "DEFAULT_KEY", "status": "valid"})
    
    key_data = keys_collection.find_one({"key": api_key})
    if not key_data:
        return jsonify({"error": "Key not found"}), 404
    
    response = {
        "key": key_data['key'],
        "created_at": key_data['created_at'].strftime("%Y-%m-%d %H:%M:%S"),
        "status": "valid"
    }
    
    if 'expiry' in key_data:
        response['expiry'] = key_data['expiry'].strftime("%Y-%m-%d %H:%M:%S")
        if key_data['expiry'] < datetime.utcnow():
            response['status'] = "expired"
    
    return jsonify(response)

@app.route('/checked', methods=['GET'])
def check_all_keys():
    keys = list(keys_collection.find({}))
    response = []
    
    for key_data in keys:
        key_info = {
            "key": key_data['key'],
            "created_at": key_data['created_at'].strftime("%Y-%m-%d %H:%M:%S"),
            "status": "valid"
        }
        
        if 'expiry' in key_data:
            key_info['expiry'] = key_data['expiry'].strftime("%Y-%m-%d %H:%M:%S")
            if key_data['expiry'] < datetime.utcnow():
                key_info['status'] = "expired"
        
        response.append(key_info)
    
    return jsonify({"keys": response, "count": len(response)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, threaded=True)
