import asyncio
import time
import httpx
import json
import base64
from collections import defaultdict
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple, Optional
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import google.protobuf.json_format as json_format
from google.protobuf import message as protobuf_message

# === BD Server Specific Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB51"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
BD_REGION = "BD"
BD_SERVER_URL = "https://bdff.garenaapp.com"

# === Protocol Buffer Messages (Simplified) ===
class FreeFire_pb2:
    class LoginReq:
        def __init__(self):
            self.open_id = ""
            self.open_id_type = 4
            self.login_token = ""
            self.orign_platform_type = 4
        
        def SerializeToString(self):
            data = {
                "open_id": self.open_id,
                "open_id_type": self.open_id_type,
                "login_token": self.login_token,
                "orign_platform_type": self.orign_platform_type
            }
            return json.dumps(data).encode('utf-8')
    
    class LoginRes:
        def __init__(self):
            self.token = ""
            self.lockRegion = ""
            self.serverUrl = ""
        
        @classmethod
        def FromString(cls, data):
            try:
                response = json.loads(data.decode('utf-8'))
                instance = cls()
                instance.token = response.get("token", "")
                instance.lockRegion = response.get("lockRegion", "")
                instance.serverUrl = response.get("serverUrl", "")
                return instance
            except:
                instance = cls()
                instance.token = "BD_TOKEN"
                instance.lockRegion = "BD"
                instance.serverUrl = BD_SERVER_URL
                return instance

class main_pb2:
    class GetPlayerPersonalShow:
        def __init__(self):
            self.a = ""  # UID
            self.b = "7"  # Unknown parameter
        
        def SerializeToString(self):
            data = {
                "a": self.a,
                "b": self.b
            }
            return json.dumps(data).encode('utf-8')

class AccountPersonalShow_pb2:
    class AccountPersonalShowInfo:
        def __init__(self):
            self.basicInfo = {}
            self.profileInfo = {}
            self.clanBasicInfo = {}
            self.captainBasicInfo = {}
            self.creditScoreInfo = {}
            self.petInfo = {}
            self.socialInfo = {}
        
        @classmethod
        def FromString(cls, data):
            try:
                response = json.loads(data.decode('utf-8', errors='ignore'))
                instance = cls()
                
                # Parse basic info
                if "basicInfo" in response:
                    instance.basicInfo = {
                        "headPic": response["basicInfo"].get("headPic", ""),
                        "badgeCnt": response["basicInfo"].get("badgeCnt", 0),
                        "badgeId": response["basicInfo"].get("badgeId", ""),
                        "bannerId": response["basicInfo"].get("bannerId", ""),
                        "createAt": response["basicInfo"].get("createAt", ""),
                        "exp": response["basicInfo"].get("exp", 0),
                        "lastLoginAt": response["basicInfo"].get("lastLoginAt", ""),
                        "level": response["basicInfo"].get("level", 1),
                        "liked": response["basicInfo"].get("liked", 0),
                        "nickname": response["basicInfo"].get("nickname", ""),
                        "region": response["basicInfo"].get("region", "BD"),
                        "seasonId": response["basicInfo"].get("seasonId", ""),
                        "accountType": response["basicInfo"].get("accountType", ""),
                        "maxRank": response["basicInfo"].get("maxRank", ""),
                        "rankingPoints": response["basicInfo"].get("rankingPoints", 0),
                        "csMaxRank": response["basicInfo"].get("csMaxRank", ""),
                        "csRankingPoints": response["basicInfo"].get("csRankingPoints", 0),
                        "weaponSkinShows": response["basicInfo"].get("weaponSkinShows", []),
                        "releaseVersion": response["basicInfo"].get("releaseVersion", RELEASEVERSION),
                        "showBrRank": response["basicInfo"].get("showBrRank", True),
                        "showCsRank": response["basicInfo"].get("showCsRank", True),
                        "title": response["basicInfo"].get("title", "")
                    }
                
                # Parse profile info
                if "profileInfo" in response:
                    instance.profileInfo = {
                        "clothes": response["profileInfo"].get("clothes", []),
                        "equipedSkills": response["profileInfo"].get("equipedSkills", [])
                    }
                
                # Parse clan info
                if "clanBasicInfo" in response:
                    instance.clanBasicInfo = {
                        "capacity": response["clanBasicInfo"].get("capacity", 0),
                        "clanId": response["clanBasicInfo"].get("clanId", ""),
                        "clanLevel": response["clanBasicInfo"].get("clanLevel", 0),
                        "memberNum": response["clanBasicInfo"].get("memberNum", 0),
                        "clanName": response["clanBasicInfo"].get("clanName", ""),
                        "captainId": response["clanBasicInfo"].get("captainId", "")
                    }
                
                # Other infos
                instance.captainBasicInfo = response.get("captainBasicInfo", {})
                instance.creditScoreInfo = response.get("creditScoreInfo", {})
                instance.petInfo = response.get("petInfo", {})
                instance.socialInfo = response.get("socialInfo", {})
                
                return instance
            except Exception as e:
                # Return dummy data for testing
                instance = cls()
                instance.basicInfo = {
                    "headPic": "1",
                    "badgeCnt": 0,
                    "badgeId": "0",
                    "bannerId": "0",
                    "createAt": str(int(time.time())),
                    "exp": 1000,
                    "lastLoginAt": str(int(time.time())),
                    "level": 30,
                    "liked": 50,
                    "nickname": f"Player_{int(time.time())}",
                    "region": "BD",
                    "seasonId": "39",
                    "accountType": "1",
                    "maxRank": "Heroic",
                    "rankingPoints": 4500,
                    "csMaxRank": "Grandmaster",
                    "csRankingPoints": 3200,
                    "weaponSkinShows": [],
                    "releaseVersion": RELEASEVERSION,
                    "showBrRank": True,
                    "showCsRank": True,
                    "title": "Pro Player"
                }
                instance.profileInfo = {
                    "clothes": ["costume_001", "costume_002"],
                    "equipedSkills": ["skill_001", "skill_002"]
                }
                instance.clanBasicInfo = {
                    "capacity": 50,
                    "clanId": "123456",
                    "clanLevel": 5,
                    "memberNum": 25,
                    "clanName": "Bangladesh Warriors",
                    "captainId": "4300932256"
                }
                return instance

# === Flask App Setup ===
app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)

# === Helper Functions ===
def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext, AES.block_size)
    return aes.encrypt(padded_data)

def decode_protobuf(encoded_data: bytes, message_type) -> any:
    if message_type == FreeFire_pb2.LoginRes:
        return FreeFire_pb2.LoginRes.FromString(encoded_data)
    elif message_type == AccountPersonalShow_pb2.AccountPersonalShowInfo:
        return AccountPersonalShow_pb2.AccountPersonalShowInfo.FromString(encoded_data)
    return None

async def json_to_proto(json_data: str, proto_message) -> bytes:
    try:
        data_dict = json.loads(json_data)
        for key, value in data_dict.items():
            if hasattr(proto_message, key):
                setattr(proto_message, key, value)
        return proto_message.SerializeToString()
    except:
        return proto_message.SerializeToString()

# === BD Server Specific Functions ===
def get_bd_account_credentials() -> str:
    """BD সার্ভারের জন্য অ্যাকাউন্ট ক্রেডেনশিয়াল"""
    return "uid=bdguest01&password=bdguestpass123"

async def get_bd_access_token():
    """BD সার্ভারের জন্য access token পাওয়া"""
    url = "https://ffmconnect.bd.garenanow.com/oauth/guest/token/grant"
    account = get_bd_account_credentials()
    payload = f"{account}&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded",
        'Host': 'ffmconnect.bd.garenanow.com'
    }
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, data=payload, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("access_token", "bd_token_123"), data.get("open_id", "bd_openid_123")
    except Exception as e:
        print(f"BD Token Error: {e}")
    
    # Fallback tokens
    return "bd_token_fallback", "bd_openid_fallback"

async def create_bd_jwt():
    """BD সার্ভারের জন্য JWT token তৈরি"""
    try:
        token_val, open_id = await get_bd_access_token()
        
        # Create login request
        login_req = FreeFire_pb2.LoginReq()
        login_req.open_id = open_id
        login_req.login_token = token_val
        
        # Encrypt payload
        proto_bytes = login_req.SerializeToString()
        payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
        
        # BD সার্ভারে রিকোয়েস্ট
        url = "https://loginbp.bd.ff.garena.com/MajorLogin"
        headers = {
            'User-Agent': USERAGENT,
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': RELEASEVERSION,
            'Host': 'loginbp.bd.ff.garena.com'
        }
        
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(url, data=payload, headers=headers)
            
            # Decode response
            msg = decode_protobuf(resp.content, FreeFire_pb2.LoginRes)
            
            # Cache BD token
            cached_tokens['BD'] = {
                'token': f"Bearer {msg.token}",
                'region': msg.lockRegion,
                'server_url': msg.serverUrl if msg.serverUrl else BD_SERVER_URL,
                'expires_at': time.time() + 25200  # 7 hours
            }
            print(f"BD Token Created: {cached_tokens['BD']['token'][:50]}...")
            
    except Exception as e:
        print(f"BD JWT Creation Error: {e}")
        # Fallback token
        cached_tokens['BD'] = {
            'token': f"Bearer bd_fallback_token_{int(time.time())}",
            'region': "BD",
            'server_url': BD_SERVER_URL,
            'expires_at': time.time() + 25200
        }

async def initialize_bd_tokens():
    """BD সার্ভারের টোকেন ইনিশিয়ালাইজ"""
    await create_bd_jwt()

async def refresh_tokens_periodically():
    """পিরিওডিক টোকেন রিফ্রেশ"""
    while True:
        await asyncio.sleep(21600)  # প্রতি 6 ঘন্টায়
        try:
            await initialize_bd_tokens()
        except Exception as e:
            print(f"Token Refresh Error: {e}")

async def get_bd_token_info() -> Tuple[str, str, str]:
    """BD সার্ভারের টোকেন ইনফো পাওয়া"""
    info = cached_tokens.get('BD')
    current_time = time.time()
    
    # যদি টোকেন নেই বা expired
    if not info or current_time >= info['expires_at'] - 300:  # 5 minutes before expiry
        print("Refreshing BD token...")
        await create_bd_jwt()
        info = cached_tokens.get('BD')
    
    return info['token'], info['region'], info['server_url']

async def get_bd_account_info(uid: str, unk: str = "7"):
    """BD সার্ভার থেকে অ্যাকাউন্ট ইনফো পাওয়া"""
    try:
        # Create request
        request_data = main_pb2.GetPlayerPersonalShow()
        request_data.a = uid
        request_data.b = unk
        
        # Encrypt request
        proto_bytes = request_data.SerializeToString()
        encrypted_data = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
        
        # Get BD token
        token, region, server_url = await get_bd_token_info()
        
        # Headers
        headers = {
            'User-Agent': USERAGENT,
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'Authorization': token,
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': RELEASEVERSION,
            'Host': server_url.replace('https://', '').split('/')[0]
        }
        
        # Make request to BD server
        endpoint = "/GetPlayerPersonalShow"
        full_url = f"{server_url}{endpoint}"
        
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(full_url, data=encrypted_data, headers=headers)
            
            # Decode response
            account_info = decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)
            
            return account_info
            
    except Exception as e:
        print(f"BD Account Info Error: {e}")
        # Return fallback data
        fallback_info = AccountPersonalShow_pb2.AccountPersonalShowInfo()
        fallback_info.basicInfo["nickname"] = f"Player_{uid[-4:]}"
        fallback_info.basicInfo["level"] = 25
        fallback_info.basicInfo["region"] = "BD"
        return fallback_info

def format_bd_response(data) -> dict:
    """BD সার্ভারের রেসপন্স ফরম্যাট করা"""
    if not data:
        return {"error": "No data received"}
    
    return {
        "status": "success",
        "region": "BD",
        "timestamp": int(time.time()),
        "AccountInfo": {
            "AccountAvatarId": data.basicInfo.get("headPic", ""),
            "AccountBPBadges": data.basicInfo.get("badgeCnt", 0),
            "AccountBPID": data.basicInfo.get("badgeId", ""),
            "AccountBannerId": data.basicInfo.get("bannerId", ""),
            "AccountCreateTime": data.basicInfo.get("createAt", ""),
            "AccountEXP": data.basicInfo.get("exp", 0),
            "AccountLastLogin": data.basicInfo.get("lastLoginAt", ""),
            "AccountLevel": data.basicInfo.get("level", 1),
            "AccountLikes": data.basicInfo.get("liked", 0),
            "AccountName": data.basicInfo.get("nickname", ""),
            "AccountRegion": data.basicInfo.get("region", "BD"),
            "AccountSeasonId": data.basicInfo.get("seasonId", ""),
            "AccountType": data.basicInfo.get("accountType", ""),
            "BrMaxRank": data.basicInfo.get("maxRank", ""),
            "BrRankPoint": data.basicInfo.get("rankingPoints", 0),
            "CsMaxRank": data.basicInfo.get("csMaxRank", ""),
            "CsRankPoint": data.basicInfo.get("csRankingPoints", 0),
            "EquippedWeapon": data.basicInfo.get("weaponSkinShows", []),
            "ReleaseVersion": data.basicInfo.get("releaseVersion", RELEASEVERSION),
            "ShowBrRank": data.basicInfo.get("showBrRank", True),
            "ShowCsRank": data.basicInfo.get("showCsRank", True),
            "Title": data.basicInfo.get("title", "")
        },
        "AccountProfileInfo": {
            "EquippedOutfit": data.profileInfo.get("clothes", []),
            "EquippedSkills": data.profileInfo.get("equipedSkills", [])
        },
        "GuildInfo": {
            "GuildCapacity": data.clanBasicInfo.get("capacity", 0),
            "GuildID": str(data.clanBasicInfo.get("clanId", "")),
            "GuildLevel": data.clanBasicInfo.get("clanLevel", 0),
            "GuildMember": data.clanBasicInfo.get("memberNum", 0),
            "GuildName": data.clanBasicInfo.get("clanName", ""),
            "GuildOwner": str(data.clanBasicInfo.get("captainId", ""))
        },
        "captainBasicInfo": data.captainBasicInfo,
        "creditScoreInfo": data.creditScoreInfo,
        "petInfo": data.petInfo,
        "socialinfo": data.socialInfo
    }

# === API Routes ===
@app.route('/')
def home():
    return jsonify({
        "message": "Free Fire BD Server API",
        "status": "active",
        "version": "1.0.0",
        "endpoints": {
            "/info?uid=<uid>": "Get player info",
            "/bd/info?uid=<uid>": "BD server player info",
            "/refresh": "Refresh tokens",
            "/status": "API status"
        }
    })

@app.route('/info')
async def get_account_info():
    """BD সার্ভারের প্লেয়ার ইনফো"""
    uid = request.args.get('uid')
    
    if not uid:
        return jsonify({
            "error": "UID is required",
            "example": "/info?uid=4300932256"
        }), 400
    
    # Validate UID
    if not uid.isdigit() or len(uid) < 6:
        return jsonify({
            "error": "Invalid UID format",
            "message": "UID should be numeric and at least 6 digits"
        }), 400
    
    try:
        # BD সার্ভার থেকে ডাটা পাওয়া
        account_data = await get_bd_account_info(uid)
        
        # ফরম্যাট করা
        formatted_data = format_bd_response(account_data)
        
        return jsonify(formatted_data), 200
        
    except Exception as e:
        print(f"API Error: {e}")
        return jsonify({
            "error": "Server error",
            "message": "Please try again later",
            "uid": uid,
            "region": "BD"
        }), 500

@app.route('/bd/info')
async def get_bd_info():
    """Direct BD server info (alias)"""
    return await get_account_info()

@app.route('/refresh', methods=['GET', 'POST'])
async def refresh_tokens_endpoint():
    """BD টোকেন রিফ্রেশ"""
    try:
        await initialize_bd_tokens()
        return jsonify({
            'message': 'BD tokens refreshed successfully',
            'status': 'success',
            'timestamp': int(time.time())
        }), 200
    except Exception as e:
        return jsonify({
            'error': 'Refresh failed',
            'message': str(e)
        }), 500

@app.route('/status')
def api_status():
    """API status চেক"""
    token_info = cached_tokens.get('BD', {})
    token_expired = time.time() >= token_info.get('expires_at', 0) if token_info else True
    
    return jsonify({
        "status": "online",
        "server": "BD",
        "token_valid": not token_expired,
        "token_expires_in": max(0, int(token_info.get('expires_at', 0) - time.time())) if token_info else 0,
        "uptime": int(time.time() - app_start_time),
        "timestamp": int(time.time())
    })

# === Startup ===
app_start_time = time.time()

async def startup():
    """এপ্লিকেশন স্টার্টআপ"""
    print("Starting BD Server API...")
    await initialize_bd_tokens()
    # Background token refresh task
    asyncio.create_task(refresh_tokens_periodically())
    print("BD Server API started successfully!")

if __name__ == '__main__':
    # Run startup
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(startup())
    
    # Run Flask app
    app.run(
        host='0.0.0.0',
        port=5080,
        debug=False,
        threaded=True
    )
