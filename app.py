#MADE BY @STAR_GMR
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import requests
from flask import Flask, jsonify, request
from data_pb2 import AccountPersonalShowInfo
from google.protobuf.json_format import MessageToDict
import uid_generator_pb2
import threading
import time

app = Flask(__name__)

jwt_token = None
jwt_lock = threading.Lock()

# ---------------- JWT CONFIG ----------------
JWT_API = "http://d1.max-cloud.xyz:2009/token"

JWT_CREDENTIALS = {
    "IND": {"uid": "4264854536", "password": "IND_PASSWORD"},
    "BD":  {"uid": "4312833186", "password": "71A366FED89EA69EC3E8CEBF80FAD999598ECCA6C2C4B52FA024AF2011B6CB9A"},
    "ME":  {"uid": "4363456802", "password": "PK_PASSWORD"},
    "PK":  {"uid": "4363456802", "password": "PK_PASSWORD"},
    "TH":  {"uid": "4363456802", "password": "PK_PASSWORD"},
    "BR":  {"uid": "4363456802", "password": "PK_PASSWORD"},
    "VN":  {"uid": "4363456802", "password": "PK_PASSWORD"},
    "SAC":  {"uid": "4363456802", "password": "PK_PASSWORD"},
    "ID":  {"uid": "4363456802", "password": "PK_PASSWORD"},
}

# ---------------- JWT HANDLING ----------------
def get_jwt_token_sync(region):
    global jwt_token

    creds = JWT_CREDENTIALS.get(region, JWT_CREDENTIALS["BD"])
    url = f"{JWT_API}?uid={creds['uid']}&password={creds['password']}"

    with jwt_lock:
        try:
            r = requests.get(url, timeout=10)
            data = r.json()
            if isinstance(data, dict) and "token" in data:
                jwt_token = data["token"]
                return jwt_token
        except Exception as e:
            print("[JWT ERROR]", e)

    return None

def ensure_jwt_token_sync(region):
    global jwt_token
    if not jwt_token:
        return get_jwt_token_sync(region)
    return jwt_token

def jwt_token_updater(region):
    while True:
        get_jwt_token_sync(region)
        time.sleep(300)

# ---------------- API ENDPOINT ----------------
def get_api_endpoint(region):
    endpoints = {
        "IND": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
        "BD":  "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "ME":  "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "PK":  "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "TH":  "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "BR":  "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "VN":  "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "SAC":  "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "ID":  "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
          }
    return endpoints.get(region, endpoints["IND"])

# ---------------- AES ----------------
AES_KEY = "Yg&tc%DEuh6%Zc^8"
AES_IV  = "6oyZDr22E3ychjM%"

def encrypt_aes(hex_data):
    cipher = AES.new(AES_KEY.encode()[:16], AES.MODE_CBC, AES_IV.encode()[:16])
    padded = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted = cipher.encrypt(padded)
    return binascii.hexlify(encrypted).decode()

# ---------------- MAIN API CALL ----------------
def call_api(enc_hex, region):
    token = ensure_jwt_token_sync(region)
    if not token:
        raise Exception("JWT token not available")

    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; Android 9)",
        "Authorization": f"Bearer {token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB53",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    r = requests.post(
        get_api_endpoint(region),
        headers=headers,
        data=bytes.fromhex(enc_hex),
        timeout=10
    )

    return r.content.hex()

# ---------------- ROUTES ----------------
@app.route("/info")
def info():
    try:
        uid = request.args.get("uid")
        region = request.args.get("region", "IND").upper()

        if not uid:
            return jsonify({"error": "UID required"}), 400

        if region not in ["IND", "BD", "PK","ME","BR","TH","VN","SAC","ID"]:
            return jsonify({"error": "Only IND, BD, PK supported"}), 400

        threading.Thread(target=jwt_token_updater, args=(region,), daemon=True).start()

        msg = uid_generator_pb2.uid_generator()
        msg.saturn_ = int(uid)
        msg.garena = 1

        hex_data = binascii.hexlify(msg.SerializeToString()).decode()
        encrypted = encrypt_aes(hex_data)

        api_hex = call_api(encrypted, region)

        pb = AccountPersonalShowInfo()
        pb.ParseFromString(bytes.fromhex(api_hex))
        data = MessageToDict(pb)

        data["Developer"] = "@RS_WONER"
        data["Channel"] = "@CARTOONFUNNY03"
        data["Region"] = region
        data["Version"] = "OB53"

        return jsonify(data)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/")
def home():
    return jsonify({
        "message": "Free Fire Account Info API",
        "developer": "@RS_WINER",
        "channel": "@CARTOONFUNNY03",
        "endpoint": "/accinfo?uid=UID&region=BD"
    })

# ---------------- RUN ----------------
if __name__ == "__main__":
    ensure_jwt_token_sync("BD")
    app.run(host="0.0.0.0", port=5000)