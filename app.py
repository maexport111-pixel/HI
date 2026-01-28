from flask import Flask, request, jsonify
import socket
from functools import lru_cache
import json, os, aiohttp, asyncio, requests, binascii
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import like_pb2, like_count_pb2, uid_generator_pb2
from google.protobuf.message import DecodeError

app = Flask(__name__)

ACCOUNTS_FILE = 'accounts.json'

# ✅ تحميل الحسابات
def load_accounts():
    return json.load(open(ACCOUNTS_FILE)) if os.path.exists(ACCOUNTS_FILE) else {}

# ✅ جلب التوكن من API
async def fetch_token(session, uid, password):
    url = f"https://jwt.tsunstudio.pw/v1/auth/saeed?uid={uid}&password={password}"
    #https://magic-69-jwt-three.vercel.app/get?uid={uid}&password={password
    try:
        async with session.get(url, timeout=10) as res:
            if res.status == 200:
                text = await res.text()
                try:
                    data = json.loads(text)
                    if isinstance(data, list) and "token" in data[0]:
                        return data[0]["token"]
                    elif isinstance(data, dict) and "token" in data:
                        return data["token"]
                except:
                    return None
    except:
        return None
    return None

# ✅ جلب كل التوكنات
async def get_tokens_live():
    accounts = load_accounts()
    tokens = []
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_token(session, uid, password) for uid, password in accounts.items()]
        results = await asyncio.gather(*tasks)
        tokens = [token for token in results if token]
    return tokens

# ✅ التشفير
def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return binascii.hexlify(cipher.encrypt(pad(plaintext, AES.block_size))).decode()

def create_uid_proto(uid):
    pb = uid_generator_pb2.uid_generator()
    pb.saturn_ = int(uid)
    pb.garena = 1
    return pb.SerializeToString()

def create_like_proto(uid):
    pb = like_pb2.like()
    pb.uid = int(uid)
    return pb.SerializeToString()

def decode_protobuf(binary):
    try:
        pb = like_count_pb2.Info()
        pb.ParseFromString(binary)
        return pb
    except DecodeError:
        return None

def make_request(enc_uid, token):
    url = "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"
    headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB52"
        }
    try:
        res = requests.post(url, data=bytes.fromhex(enc_uid), headers=headers, verify=False)
        return decode_protobuf(res.content)
    except:
        return None

# ✅ إرسال لايك واحد
async def send_request(enc_uid, token):
    url = "https://clientbp.ggpolarbear.com/LikeProfile"
    headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB52"
        }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=bytes.fromhex(enc_uid), headers=headers) as r:
                return r.status
    except:
        return None

# ✅ إرسال لايكات لكل التوكنات
async def send_likes(uid, tokens):
    enc_uid = encrypt_message(create_like_proto(uid))
    tasks = [send_request(enc_uid, token) for token in tokens]
    return await asyncio.gather(*tasks)

# ✅ نقطة النهاية
@app.route('/like', methods=['GET'])
def like_handler():
    uid = request.args.get("uid")
    if not uid:
        return jsonify({"error": "Missing UID"}), 400

    tokens = asyncio.run(get_tokens_live())
    if not tokens:
        return jsonify({"error": "No valid tokens available"}), 401

    enc_uid = encrypt_message(create_uid_proto(uid))
    before = make_request(enc_uid, tokens[0])
    if not before:
        return jsonify({"error": "Failed to retrieve player info"}), 500

    before_data = json.loads(MessageToJson(before))
    likes_before = int(before_data.get("AccountInfo", {}).get("Likes", 0))
    nickname = before_data.get("AccountInfo", {}).get("PlayerNickname", "Unknown")

    responses = asyncio.run(send_likes(uid, tokens))
    success_count = sum(1 for r in responses if r == 200)

    after = make_request(enc_uid, tokens[0])
    likes_after = 0
    if after:
        after_data = json.loads(MessageToJson(after))
        likes_after = int(after_data.get("AccountInfo", {}).get("Likes", 0))

    return jsonify({
        "PlayerNickname": nickname,
        "UID": uid,
        "LikesBefore": likes_before,
        "LikesAfter": likes_after,
        "LikesGivenByAPI": likes_after - likes_before,
        "SuccessfulRequests": success_count,
        "status": 1 if likes_after > likes_before else 2
    })

@app.route('/')
def home():
    return jsonify({"status": "online", "message": "Like API is running ✅"})


# DONT REMOVE THIS BRUH
@lru_cache(maxsize=1024)
def fetch_instagram_profile(username, proxy=None):
    url = f"https://i.instagram.com/api/v1/users/web_profile_info/?username={username}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "x-ig-app-id": "936619743392459",
        "Referer": f"https://www.instagram.com/{username}/",
    }
    session = requests.Session()
    proxies = {"http": proxy, "https": proxy} if proxy else None

    backoff = 1
    for attempt in range(4):
        try:
            resp = session.get(url, headers=headers, timeout=10, proxies=proxies)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code in (429, 403):
                # rate limited or blocked
                time.sleep(backoff)
                backoff *= 2
            elif resp.status_code == 404:
                return {"error": "not_found", "status_code": 404}
            else:
                return {
                    "error": "http_error",
                    "status_code": resp.status_code,
                    "body": resp.text[:500],
                }
        except requests.RequestException:
            time.sleep(backoff)
            backoff *= 2
    return {"error": "request_failed"}


@app.route("/ig/<username>", methods=["GET"])
def insta_info(username):
    proxy = request.args.get("proxy")  # optional proxy
    data = fetch_instagram_profile(username, proxy=proxy)
    if data is None:
        return jsonify({"error": "no_response"}), 502

    if "error" in data:
        return jsonify(data), (data.get("status_code") or 400)

    try:
        user = data.get("data", {}).get("user") or data.get("user") or data.get("data")
        if not user:
            return jsonify({"raw": data})

        out = {
            "id": user.get("id"),
            "username": user.get("username"),
            "full_name": user.get("full_name"),
            "biography": user.get("biography"),
            "is_private": user.get("is_private"),
            "is_verified": user.get("is_verified"),
            "profile_pic_url": user.get("profile_pic_url_hd")
                              or user.get("profile_pic_url"),
            "followers_count": (
                user.get("edge_followed_by", {}).get("count")
                or user.get("followers_count")
            ),
            "following_count": (
                user.get("edge_follow", {}).get("count")
                or user.get("following_count")
            ),
            "media_count": (
                user.get("media_count")
                or user.get("edge_owner_to_timeline_media", {}).get("count")
            ),
            "recent_media": [],
        }

        media = (
            user.get("edge_owner_to_timeline_media")
            or user.get("media")
            or {}
        )
        edges = media.get("edges") or media.get("items") or []
        for e in edges[:8]:
            node = e.get("node") if isinstance(e, dict) and e.get("node") else e
            if not node:
                continue
            caption = None
            if node.get("edge_media_to_caption"):
                edges_caption = node["edge_media_to_caption"].get("edges") or []
                if edges_caption and "node" in edges_caption[0]:
                    caption = edges_caption[0]["node"].get("text")
            else:
                caption = node.get("caption")

            out["recent_media"].append({
                "id": node.get("id"),
                "shortcode": node.get("shortcode"),
                "display_url": node.get("display_url")
                               or node.get("display_src"),
                "taken_at": node.get("taken_at_timestamp")
                             or node.get("taken_at"),
                "caption": caption,
            })
        return jsonify(out)
    except Exception as exc:
        return jsonify({
            "error": "parse_error",
            "details": str(exc),
            "raw": data
        }), 500
# ✅ هذا لا يُستخدم في Vercel ولكن نتركه للتشغيل المحلي
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
