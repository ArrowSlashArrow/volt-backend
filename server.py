import asyncio, json, websockets, random, requests, base64, os, time, ssl, sys, hashlib

BINDIP = "0.0.0.0"
PORT = 2096

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

config_boilerplate = {
    "channels": {
        "general": {
            "whitelist": [],
            "whitelist_enabled": False,
            "blacklist": [],
            "blacklist_enabled": True,
        }
    }, 
    "banned_ips": [],
    "banned_users": [],
    "admins": []
}
config = read_or_create(config_file, config_boilerplate)

connected_users = {}

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
    json.dump(config, open(users_file, "w"))

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
    ip = ws.remote_address[0]
    user_struct = {
        "websocket": ws,
        "key": "",
        "ip": ip,
        "loggedin": False,
        "admin": False
    }
    
    async def send_json(data):
        await ws.send(json.dumps(data))
        
    async def check_session(msg, what, check_logged_in=True):
        if msg["session"] != session or session == "":
            print("bad session")
            await send_json({"success": False, "reason": "Bad session", "what": what})
            return True
        if check_logged_in and not user_struct["loggedin"]:
            await send_json({"success": False, "reason": "Not logged in", "what": what})
            return True
        return False

    async def check_session_admin(msg, what):
        if msg["session"] != session or session == "" or not user_struct["admin"]:
            print("bad session")
            await send_json({"success": False, "reason": "Bad session", "what": what})
            return True
        return False
    
    async def broadcast_msg(msg):
        removelist = []    
        for user, connection in connected_users.items():
            try:
                await connection["websocket"].send(json.dumps(msg))
            except Exception as e:
                print(f"bad happened: {e}")
                removelist.append(ip)
                
        for user in removelist:
            connected_users.pop(user, None)
            
    def get_user_info(user):
        return connected_users.get(user, {})
            
    async def kick(user):
        user_info = get_user_info(user)
        await user_info["websocket"].close(code=1000, reason=b"bye bye")
            
        channel = messages["channels"][0]
        ip = user_info["ip"]
        dc_msg = disconnect_msg(user)
        
        print(f"{ip} was kicked")
        connected_users.pop(ip, None)
        
        messages["msgs"][channel].append(stringify_json(dc_msg))
        await broadcast_msg({
            "what": "new_msg",
            "channel": channel,
            "msg": json.dumps(dc_msg)
        })
        
    # returns true if the channel was craeted, false if it already exists
    def new_channel(name, whitelist_enabled=False, whitelist=[]):
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

    
    
    if ip in config["banned_ips"]:
        await send_json({"success": False, "reason": "We tolerate you no more.", "what": "connect"})
        return
    
    if ip in connected_users:
        await send_json({"success": False, "reason": "already connected", "what": "connect"})
        return
    
    await send_json({"success": True, "what": "connect"})
    
    
    print(f"{ip} connected")
    session = ""
    username = ""
    
    try:
        async for raw_msg in ws:
            msg = json.loads(raw_msg)
            print(f"{ip} sent {msg}")
            
            match msg.get("action", ""):
                case "session":  # only happens at inital connect
                    session = random_session()
                    try:
                        # key = base64.b64decode(msg["key"].encode())
                        # connected_users[ip]["key"] = key
                        await send_json({
                            "success": True, 
                            "session": session, 
                            "what": "session"
                        })
                    
                    except Exception as e:
                        print(f"no session given because {e}")
                        await send_json({
                            "success": False, 
                            "what": "session",
                            "reason": "Client did not provide public key."
                        })
                        
                    user_struct["session"] = session
                    
                case "login":
                    if await check_session(msg, "login", False):
                        continue
                    
                    if "username" not in msg or "password" not in msg:
                        await send_json({"success": False, "reason": "Malformed request", "what": "login"})
                        continue
                    
                    user = msg["username"]
                    password = hashlib.sha256(bytes(msg["password"])).hexdigest().encode()
                    
                    if user in connected_users:
                        await send_json({"success": False, "reason": "Already logged in", "what": "login"})
                        continue
                    
                    if user in config["banned_users"]:
                        await send_json({"success": False, "reason": "Banned", "what": "login"})
                        continue
                    
                    if user in users:
                        if users[user]["pwd"] != password:
                            print("bad password")
                            
                            await send_json({"success": False, "reason": "Incorrect password", "what": "login"})
                            continue
                        else:
                            print("balright password")
                    else:
                        print("new account")
                        users[user] = {"pwd": password, "id": len(users)}
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
                    
                    
                    user_struct["loggedin"] = True
                    connected_users[user] = user_struct
                    
                    username = user
                    
                    if username in config["admins"]:
                        user_struct["admin"] = True
                        
                case "data":
                    if await check_session(msg, "data"):
                        continue
                    
                    channels = get_whitelisted_channels(config, username)
                    print(f"sending messages to {ip} from these channels: {channels}")
                    data = last_n_msgs(channels, 1000)
                    data["users"] = [user for user in connected_users.keys()]
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
                    if user_info == {}:
                        continue
                    
                    config["banned_ips"].append(user_info["ip"])
                    save_config()
                    await kick(user_info["user"])
                    
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
                    if user_info == {}:
                        continue
                    
                    if user_info["ip"] in config["banned_ips"]:
                        config["banned_ips"].remove(user_info["ip"])
                        save_config()
                    
                case "dm":
                    if await check_session(msg, "dm"):
                        continue
                    
                    if "user" not in msg:
                        continue 
                    
                    user_info = get_user_info(msg["user"])
                    if user_info == {}:
                        continue
                    
                    other = user_info["user"]
                    channel_name = f"{user} <-> {other} DM"
                    
                    if new_channel(channel_name, True, [user, other]):
                        await ws.send(json.dumps({"what": "newchannel", "channel_name": channel_name}))
                        await user_info["websocket"].send(json.dumps({"what": "newchannel", "channel_name": channel_name}))
                    
                case "newchannel":
                    if await check_session_admin(msg, "newchannel"):
                        continue

                    channel_name = msg["channelname"]
                    if new_channel(channel_name):
                        await broadcast_msg({"what": "newchannel", "channel_name": channel_name})
    
    finally:
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
    try:
        public_ip = requests.get('https://api.ipify.org').text
        print(f"public IP: {public_ip} (connect here as a client)")
    except:
        pass

    async with websockets.serve(main, BINDIP, PORT):
        print("server started")
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            await kick_everyone()
        
async def kick_everyone():
    save_config()
    save_messages()
    save_users()
    for ip, ws in connected_users.items():
        print(f"kicking {ip}")
        await ws["websocket"].close(code=1000, reason="internal error")

try:
    if __name__ == "__main__":
        asyncio.run(_main())

except Exception as e:
    
    print(f"crash becase {e}")