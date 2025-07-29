import asyncio, json, websockets, random, requests
from nacl.public import PrivateKey

public_ip = requests.get('https://api.ipify.org').text
print(f"public IP: {public_ip} (connect here as a client)")

def generate_keys():
    private = PrivateKey.generate()
    public = private.public_key
    return (bytes(private).hex(), bytes(public).hex())

def read_or_create(path, fallback={}):
    data = fallback
    try:
        data = json.load(open(path, "r"))
    except:
        json.dump(data, open(path, "w"))
    return data

default_msgs = {"channels": ["general"], "msgs": {}}

users_file = "users.json"
messages_file = "messages.json"
users = read_or_create(users_file)
messages = read_or_create(messages_file, default_msgs)

keys_fallback = {"keys": {channel: generate_keys() for channel in messages["channels"]}}
keys = read_or_create("keys.json", keys_fallback)["keys"]

connected_users = {}

def random_session():
    return f"{random.randint(0, 2**256):x}"

def save_users():
    json.dump(users, open(users_file, "w"))
    
def save_messages():
    json.dump(messages, open(messages_file, "w"))
    
def last_1000_msgs():
    last = {}
    for k, v in messages["msgs"].items():
        last[k] = v if len(v) <= 1000 else v[-1000:]
    return last

async def main(ws):
    async def send_json(data):
        await ws.send(json.dumps(data))
        
    async def check_session(msg):
        if msg["session"] != session or session == "":
            print("bad session")
            await send_json({"success": False, "reason": "Bad session"})
            return True
        return False
    
    async def broadcast_msg(msg):
        removelist = []    
        for ip, socket in connected_users.items():
            try:
                await socket.send(json.dumps(msg))
            except Exception as e:
                print(f"bad happened: {e}")
                removelist.append(ip)
                
        for ip in removelist:
            connected_users.pop(ip, None)
    
    ip = ws.remote_address[0]
    if ip in connected_users:
        await ws.send("already connected")
        return
    
    await ws.send("good to go")
    connected_users[ip] = ws
    
    print(f"{ip} connected")
    
    session = ""
    loggedin = False
    try:
        async for raw_msg in ws:
            msg = json.loads(raw_msg)
            print(f"{ip} sent {msg}")
            
            match msg["action"]:
                case "session":
                    session = random_session()
                    await send_json({"success": True, "session": session})
                case "login":
                    if await check_session(msg):
                        continue
                    
                    user = msg["username"]
                    password = msg["password"]
                    
                    if user in users:
                        if users[user][0] != password:
                            print("bad password")
                            
                            await send_json({"success": False, "reason": "Incorrect Password"})
                            continue
                    else:
                        print("new account")
                        users[user] = [password, len(users)]
                        save_users()
                        
                    print("good")
                    await send_json({"success": True})
                    loggedin = True
                        
                case "data":
                    if await check_session(msg):
                        continue
                    if not loggedin:
                        await send_json({"success": False, "reason": "Not logged in"})
                        continue
                    
                    await send_json(messages)
                    
                case "message":
                    if await check_session(msg):
                        continue
                    if not loggedin:
                        await send_json({"success": False, "reason": "Not logged in"})
                        continue
                    
                    sanitised = str(msg["msg"])
                    messages["msgs"][msg["channel"]].append(sanitised)
                    await broadcast_msg({"what": "new_msg", "channel": msg["channel"], "msg": sanitised})
                    save_messages()
                    
    except Exception as e:
        print(f"error: {e}")
                    
    finally:
        print(f"{ip} disconnected")
        connected_users.pop(ip, None)
    
async def _main():
    async with websockets.serve(main, "0.0.0.0", 2096):
        print("server started")
        await asyncio.Future()

try:
    if __name__ == "__main__":
        asyncio.run(_main())
except Exception as e:
    print("global bad: {e}")
    for ip, ws in connected_users.items():
        ws.close(code=1000, reason=b"server shutdown")