import asyncio, json, websockets, random, requests, base64, os, time, ssl, sys, hashlib

PORT = 2096
BIND_IP = "127.0.0.1"

def read_or_create(path, fallback={}):
    data = fallback
    try:
        data = json.load(open(path, "r"))
    except:
        json.dump(data, open(path, "w"))
    return data

default_msgs = {"channels": ["general"], "msgs": {"general": []}}

users_file = "users.json"
messages_file = "messages.json"
config_file = "config.json"

users = read_or_create(users_file)
messages = read_or_create(messages_file, default_msgs)

config_boilderplate = {
    "channels": {
        "general": {
            "whitelist_enabled": False,
            "whitelist": [],
            "blacklist_enabled": True,
            "blacklist": []
        }
    },
    "banned_ips": [],
    "banned_users": [],
    "admins": []
}
config = read_or_create(config_file)
connected_users = {}
anonymous_users = []

class ConnectedUser:
    def __init__(self, session, ip, socket, loggedin, admin):
        self.session = session
        self.ip = ip
        self.socket = socket
        self.loggedin = loggedin
        self.admin = admin
        
    async def send_json(self, json_data):
        await self.socket.send(json.dumps(json_data))
        
    async def kick(self):
        await self.socket.close(code=1000, reason=b"bye bye")

def get_whitelisted_channels(cfg, user):
    whitelisted = []
    for channel, rules in cfg["channels"].items():
        if rules["blacklist_enabled"] and user in rules["blacklist"]:
            continue
        elif rules["whitelist_enabled"] and user not in rules["whitelist"]:
            continue            
        whitelisted.append(channel)
    return whitelisted

def random_session():
    return f"{random.randint(0, 2**256):x}"

def save_users():
    # this file stores the passwords only so i can manually encode it
    file = "{"
    for user, pw in users.items():
        file += f"\n    \"{user}\": [\n        {pw[0]},\n        {pw[1]}\n    ],"
    file = file[:-1]
    file += "\n}"
    open(users_file, "w").write(file)

def save_config():
    json.dump(config, open(config_file, "w"), indent=4)
    
def save_messages():
    json.dump(messages, open(messages_file, "w"), indent=4)
    
def stringify_json(d):
    return json.dumps(d)
    
def last_n_msgs(channels, n):
    last = {"channels": channels, "msgs": {}}
    for channel in channels:
        channel_msgs = messages["msgs"].get(channel, [])
        last["msgs"][channel] = channel_msgs if len(channel_msgs) <= n else channel_msgs[-n:]
    return last

def connect_msg(user):
    return {"user": user, "time": int(time.time() * 1000), "msg": "hello", "replying_to": "-1", "type": "Connect"}

def disconnect_msg(user):
    return {"user": user, "time": int(time.time() * 1000), "msg": "bye bye", "replying_to": "-1", "type": "Disconnect"}

async def main(ws):
    async def send_json(data):
        print(f"sending {data}")
        await ws.send(json.dumps(data))
        
    async def check_session(msg, what, check_logged_in=True):
        if msg.get("session", "") != session or session == "":
            print("bad session")
            await send_json({"success": False, "reason": "Bad session", "what": what})
            return True
        if check_logged_in and not curr_user.loggedin:
            await send_json({"success": False, "reason": "Not logged in", "what": what})
            return True
        return False

    async def check_session_admin(msg, what):
        if msg["session"] != session or session == "" or not curr_user.admin:
            print("bad session")
            await send_json({"success": False, "reason": "Bad session", "what": what})
            return True
        return False
    
    async def broadcast_msg(msg):
        removelist = []    
        for username, connection in connected_users.items():
            try:
                await connection.send_json(msg)
            except Exception as e:
                print(f"Failed to send message to {username}: {e}")
                removelist.append(username)
                
        for user in removelist:
            connected_users.pop(user, None)
            
    def get_user_info(username):
        return connected_users.get(username)
            
    async def kick(username):
        if username not in connected_users:
            await send_json({"success": False, "reason": "This user is not connected", "what": "kickattempt"})
            return
        
        user_info = connected_users[username]
        await user_info.kick()
            
        channel = messages["channels"][0]
        dc_msg = disconnect_msg(username)
        
        print(f"{username} was kicked")
        connected_users.pop(username, None)
        
        messages["msgs"][channel].append(stringify_json(dc_msg))
        await broadcast_msg({
            "what": "new_msg",
            "channel": channel,
            "msg": json.dumps(dc_msg)
        })
        
    # returns true if the channel was craeted, false if it already exists
    def new_channel(name, whitelist_enabled=False, whitelist=None):
        whitelist = whitelist or []
        if name in config["channels"]:
            return False
        
        config["channels"][name] = {
            "whitelist_enabled": whitelist_enabled, 
            "whitelist": whitelist,
            "blacklist_enabled": True,
            "blacklist": []
        }
        messages["channels"].append(name)
        messages["msgs"][name] = []
        save_config()
        save_messages()
        return True
    
    async def init_session():
        session = random_session()
        try:
            # key = base64.b64decode(msg["key"].encode())
            # connected_users[ip]["key"] = key
            await send_json({
                "success": True, 
                "session": session, 
                "what": "session"
            })
            return session
        
        except Exception as e:
            print(f"no session given because {e}")
            await send_json({
                "success": False, 
                "what": "session",
                "reason": "Client did not provide public key."
            })
            return None

    ip = ws.remote_address[0]
    
    # none of this ip shit works rn
    # if ip in config["banned_ips"]:
    #     await send_json({"success": False, "reason": "We tolerate you no more.", "what": "connect"})
    #     return
    
    # if any(user.ip == ip for user in connected_users):
    #     await send_json({"success": False, "reason": "already connected", "what": "connect"})
    #     return
    
    session = await init_session()
    if not session:
        await send_json({"success": False, "reason": "failed to get session", "what": "connect"})
        return    
    
    await send_json({"success": True, "what": "connect"})
    
    curr_user = ConnectedUser(
        session=session, 
        ip=ip, 
        socket=ws, 
        loggedin=False, 
        admin=False
    )
    anonymous_users.append(curr_user)
    username = ""
    
    print(f"{ip} connected")
    
    try:
        async for raw_msg in ws:
            msg = json.loads(raw_msg)
            print(f"{ip} sent {msg}")
            
            match msg.get("action", ""):                    
                case "login":
                    if await check_session(msg, "login", False):
                        continue
                    
                    if "username" not in msg or "password" not in msg:
                        await send_json({"success": False, "reason": "Malformed request", "what": "login"})
                        continue
                    
                    try:
                        password = hashlib.sha256(bytes(msg["password"])).hexdigest()
                    except Exception as e:
                        print(f"bad password: {e}")
                        await send_json({"success": False, "reason": "Malformed request", "what": "login"})
                        continue
                    
                    user = msg["username"]
                    
                    if get_user_info(user):
                        await send_json({"success": False, "reason": "Already logged in", "what": "login"})
                        continue
                    
                    if user in config["banned_users"]:
                        await send_json({"success": False, "reason": "Banned", "what": "login"})
                        continue
                    
                    if user in users:
                        if users[user][0] != password:
                            print(users[user][0], password)
                            print("bad password")
                            
                            await send_json({"success": False, "reason": "Incorrect password", "what": "login"})
                            continue
                    else:
                        print("new account")
                        users[user] = [password, len(users)]
                        save_users()
                        
                    print("good")
                    await send_json({"success": True, "what": "login"})
                    
                    connected_msg = connect_msg(user)
                    
                    await broadcast_msg({
                        "what": "new_msg",
                        "channel": messages["channels"][0],
                        "msg": json.dumps(connected_msg)
                    })
                    messages["msgs"][messages["channels"][0]].append(stringify_json(connected_msg))
                    
                    curr_user.loggedin = True
                    username = user
                    connected_users[user] = curr_user
                    anonymous_users.remove(curr_user) 
                    
                    if user in config["admins"]:
                        curr_user.admin = True
                        
                case "data":
                    if await check_session(msg, "data"):
                        continue
                    
                    channels = get_whitelisted_channels(config, username)
                    print(f"sending messages to {ip} from these channels: {channels}")
                    data = last_n_msgs(channels, 1000)
                    data["users"] = list(connected_users.keys())
                    data["what"] = "data"
                    await send_json(data)
                    print("sent")
                    
                case "message":
                    if await check_session(msg, "new_msg"):
                        continue
                    
                    sanitised = str(msg["msg"])
                    messages["msgs"][msg["channel"]].append(sanitised)
                    await broadcast_msg({"what": "new_msg", "channel": msg["channel"], "msg": sanitised})
                    save_messages()
                    
                case "kick":
                    if await check_session_admin(msg, "kick"):
                        continue
                    
                    await kick(msg["user"])
                    
                case "ban":
                    if await check_session_admin(msg, "ban"):
                        continue
                    
                    config["banned_users"].append(msg["user"])
                    save_config()
                    await kick(msg["user"])
                    
                case "banip":
                    if await check_session_admin(msg, "banip"):
                        continue
                    
                    user_info = get_user_info(msg["user"])
                    if not user_info:
                        continue
                    
                    config["banned_ips"].append(user_info.ip)
                    save_config()
                    await kick(msg["user"])
                    
                case "unban":
                    if await check_session_admin(msg, "unban"):
                        continue
                    
                    if msg["user"] in config["banned_users"]:
                        config["banned_users"].remove(msg["user"])
                        save_config()
                    
                case "unbanip":
                    if await check_session_admin(msg, "unbanip"):
                        continue
                    
                    user_info = get_user_info(msg["user"])
                    if not user_info:
                        continue
                    
                    if user_info.ip in config["banned_ips"]:
                        config["banned_ips"].remove(user_info.ip)
                        save_config()
                    
                case "dm":
                    if await check_session(msg, "dm"):
                        continue
                    
                    if "user" not in msg:
                        continue 
                    
                    user_info = get_user_info(msg["user"])
                    if not user_info:
                        continue
                    
                    other = msg["user"]
                    channel_name = f"{user} <-> {other} DM"
                    payload = {"what": "newchannel", "channel_name": channel_name}
                    
                    if new_channel(channel_name, True, [user, other]):
                        await curr_user.send_json(payload)
                        await user_info.send_json(payload)
                    
                case "newchannel":
                    if await check_session_admin(msg, "newchannel"):
                        continue

                    channel_name = msg["channelname"]
                    if new_channel(channel_name):
                        await broadcast_msg({"what": "newchannel", "channel_name": channel_name})
                    
    finally:
        if curr_user in anonymous_users:
            anonymous_users.remove(curr_user)
            return
        
        channel = ws.close_reason
        dc_msg = disconnect_msg(username)
        
        print(f"{username} disconnected")
        connected_users.pop(username, None)
        
        if channel != "":
            messages["msgs"][channel or messages["channels"][0]].append(stringify_json(dc_msg))
            await broadcast_msg({
                "what": "new_msg",
                "channel": channel,
                "msg": json.dumps(dc_msg)
            })  
        
async def _main():
    certfile, keyfile = "cert.pem", "privkey.pem"
    if "--localhost" in sys.argv:
        certfile, keyfile = "localhost.pem", "localhost-key.pem"
        
    if not os.path.exists(certfile):
        print(f"No certificate file found. Please create a new {certfile}")
        return
    
    if not os.path.exists(keyfile):
        print(f"No certificate file found. Please create a new {keyfile}")
        return
    
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    ssl_context.verify_mode = ssl.CERT_NONE

    try:
        public_ip = requests.get('https://api.ipify.org').text
        print(f"public IP: {public_ip} (connect here as a client)")
    except:
        pass

    async with websockets.serve(main, BIND_IP, PORT, ssl=ssl_context):
        print("server started")
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            await kick_everyone()
        
async def kick_everyone():
    save_config()
    save_messages()
    save_users()
    for username, data in connected_users.items():
        print(f"kicking {username}")
        await data.kick()

try:
    if __name__ == "__main__":
        asyncio.run(_main())

except Exception as e:
    
    print(f"crash becase {e}")