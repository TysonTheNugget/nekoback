from flask import Flask, render_template, jsonify, request, send_file
import os, random, time, hmac, hashlib, json, re, uuid
import requests
import urllib.parse
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)

# ========= TEST CONFIG (move to env in prod) =========
APP_FEE_ADDRESS = os.getenv("APP_FEE_ADDRESS", "bc1p7w28we62hv7vnvm4jcqrn6e8y5y6qfvvuaq8at0jpj8jyq5lymusp5jsvq")
APP_FEE_SATS = int(os.getenv("APP_FEE_SATS", "6000"))
WL_FEE_SATS = int(os.getenv("WL_FEE_SATS", "600"))
APP_SECRET = os.getenv("APP_SECRET", "local-dev-secret-change-me")
BITCOIN_NETWORK = os.getenv("BITCOIN_NETWORK", "mainnet")
INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "")
UPSTASH_URL = os.getenv("UPSTASH_REDIS_REST_URL", "https://game-raptor-60247.upstash.io")
UPSTASH_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN", "AetXAAIncDFhNWNhODAzMGU4MDc0ZTk4YWY1NDc3YzM0M2RmNjQwNHAxNjAyNDc")
TOTAL_SUPPLY = int(os.getenv("TOTAL_SUPPLY", "10000"))
SERIAL_REGEX = re.compile(r"\b(\d{10})\b")
RUN_SCHEDULER = os.getenv("RUN_SCHEDULER", "1") not in ("0", "false", "False", "")
HIRO_API_TOKEN = "1423e3815899d351c41529064e5b9a52"

# =====================================================
current_directory = os.path.dirname(os.path.abspath(__file__))
SINGLES_DIR = os.path.join(current_directory, 'static', 'Singles')
os.makedirs(SINGLES_DIR, exist_ok=True)

# ---------- Upstash helpers ----------
def _rz_result(payload):
    if isinstance(payload, dict) and "result" in payload:
        return payload["result"]
    return payload

def rz_get(path):
    r = requests.get(f"{UPSTASH_URL}{path}",
                     headers={"Authorization": f"Bearer {UPSTASH_TOKEN}"},
                     timeout=15)
    r.raise_for_status()
    return _rz_result(r.json())

def rz_post_pipeline(cmds):
    r = requests.post(f"{UPSTASH_URL}/pipeline",
                      headers={"Authorization": f"Bearer {UPSTASH_TOKEN}",
                               "Content-Type":"application/json"},
                      data=json.dumps(cmds),
                      timeout=20)
    r.raise_for_status()
    data = r.json()
    return [_rz_result(item) for item in data]

def rz_exists(key):
    res = rz_get(f"/exists/{key}")
    return int(res) == 1

def rz_sismember(key, member):
    res = rz_get(f"/sismember/{key}/{member}")
    return int(res) == 1

def rz_sadd(key, member):
    return rz_get(f"/sadd/{key}/{member}")

def rz_scard(key):
    res = rz_get(f"/scard/{key}")
    return int(res)

def rz_setex_nx(key, value, ttl_sec):
    resp = rz_post_pipeline([["SET", key, value, "NX", "EX", str(ttl_sec)]])
    return bool(resp and resp[0] == "OK")

def rz_setex(key, value, ttl_sec):
    return rz_get(f"/set/{key}/{value}?ex={ttl_sec}")

def rz_del(key):
    return rz_get(f"/del/{key}")

def rz_hgetall(key):
    res = rz_get(f"/hgetall/{key}")
    if isinstance(res, dict):
        return res
    if isinstance(res, list):
        it = iter(res)
        d = {}
        for k in it:
            try:
                v = next(it)
            except StopIteration:
                v = None
            d[str(k)] = v
        return d
    return {}

def rz_get_json(key):
    val = rz_get(f"/get/{key}")
    if val in (None, "null"):
        return None
    if isinstance(val, (dict, list)):
        return val
    try:
        return json.loads(val)
    except:
        return val

def scan_keys(match_pattern="tx:*", count=1000):
    cursor = "0"
    headers = {"Authorization": f"Bearer {UPSTASH_TOKEN}"}
    while True:
        url = f"{UPSTASH_URL}/scan/{cursor}?count={count}"
        if match_pattern:
            url += f"&match={match_pattern}"
        r = requests.get(url, headers=headers, timeout=15)
        r.raise_for_status()
        data = r.json()
        if isinstance(data, dict) and "result" in data:
            res = data["result"]
            if isinstance(res, dict):
                cursor = str(res.get("cursor", "0"))
                keys = res.get("keys", [])
            elif isinstance(res, list) and len(res) >= 2:
                cursor = str(res[0])
                keys = res[1]
            else:
                raise ValueError(f"Unexpected SCAN result payload: {res}")
        elif isinstance(data, list) and len(data) >= 2:
            cursor = str(data[0])
            keys = data[1]
        else:
            raise ValueError(f"Unexpected SCAN payload: {data}")
        yield keys
        if cursor == "0":
            break

def rz_hset_many(key: str, mapping: dict):
    flat = []
    for k, v in mapping.items():
        if isinstance(v, (dict, list)):
            v = json.dumps(v)
        else:
            v = str(v)
        flat.extend([k, v])
    resp = rz_post_pipeline([["HSET", key] + flat])
    return resp and resp[0]

def rz_ttl(key: str) -> int:
    try:
        res = rz_get(f"/ttl/{key}")
        return int(res)
    except Exception:
        return -2

# ---------- app helpers ----------
def sign_data(payload: str) -> str:
    return hmac.new(APP_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()

def list_pngs(directory):
    return [f for f in os.listdir(directory) if f.lower().endswith(".png")]

def extract_serial_from_filename(fname: str):
    m = SERIAL_REGEX.search(fname)
    if m:
        return m.group(1)
    base = os.path.splitext(os.path.basename(fname))[0]
    return base

def fetch_tx_outputs(txid: str):
    base = "https://blockstream.info/api" if BITCOIN_NETWORK.lower() == "mainnet" else "https://blockstream.info/testnet/api"
    r = requests.get(f"{base}/tx/{txid}", timeout=20)
    r.raise_for_status()
    j = r.json()
    outs = []
    for vout in j.get("vout", []):
        outs.append({
            "address": vout.get("scriptpubkey_address"),
            "value": vout.get("value", 0)
        })
    return outs

def tx_pays_app_fee(txid: str, wl=False) -> bool:
    try:
        outputs = fetch_tx_outputs(txid)
    except Exception:
        return False
    fee_sats = WL_FEE_SATS if wl else APP_FEE_SATS
    total_to_app = sum(o["value"] for o in outputs if o.get("address") == APP_FEE_ADDRESS)
    return total_to_app >= fee_sats

def is_serial_used(serial: str) -> bool:
    return rz_sismember("used_serials", serial)

def is_serial_on_hold(serial: str) -> bool:
    return rz_exists(f"hold:{serial}")

def try_hold_serial(serial: str, holder_id: str, ttl=900) -> bool:
    payload = json.dumps({"holder": holder_id, "ts": int(time.time()), "exp": int(time.time()) + ttl})
    return rz_setex_nx(f"hold:{serial}", payload, ttl)

def create_reservation_id(serial: str, ttl=900, wl=False) -> str:
    rid = str(uuid.uuid4())
    rz_setex(f"resv:{rid}", json.dumps({"serial": serial, "wl": wl}), ttl)
    return rid

def pick_available_filename(preferred_fname=None, max_attempts=100):
    files = list_pngs(SINGLES_DIR)
    random.shuffle(files)
    candidates = []
    if preferred_fname and preferred_fname in files:
        candidates.append(preferred_fname)
    candidates += [f for f in files if f != preferred_fname]
    attempts = 0
    for fname in candidates:
        attempts += 1
        if attempts > max_attempts:
            break
        serial = extract_serial_from_filename(fname)
        if is_serial_used(serial):
            continue
        if is_serial_on_hold(serial):
            continue
        return fname, serial
    raise RuntimeError("No available images to reserve")

# ---------- Whitelist helpers ----------
def load_wl_inscriptions():
    json_path = os.path.join(SINGLES_DIR, 'clean_inscriptions.json')
    try:
        with open(json_path, 'r') as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("clean_inscriptions.json must contain a list of inscription objects")
        inscription_ids = [item["id"] for item in data if isinstance(item, dict) and "id" in item]
        print(f"[WL] Loaded {len(inscription_ids)} inscriptions from clean_inscriptions.json: {inscription_ids[:5]}...")
        return inscription_ids
    except Exception as e:
        print(f"[WL] Error loading clean_inscriptions.json: {e}")
        return []

def fetch_wallet_inscriptions(address: str):
    limit = 60
    offset = 0
    all_inscriptions = []
    while True:
        try:
            response = requests.get(
                f"https://api.hiro.so/ordinals/v1/inscriptions?address={urllib.parse.quote(address)}&limit={limit}&offset={offset}",
                headers={
                    'Accept': 'application/json',
                    'Authorization': f'Bearer {HIRO_API_TOKEN}'
                },
                timeout=15
            )
            response.raise_for_status()
            data = response.json()
            inscriptions = data.get("results", [])
            print(f"[WL] Fetched {len(inscriptions)} inscriptions for {address} at offset {offset}: {[ins['id'] for ins in inscriptions][:5]}...")
            if not inscriptions:
                break
            all_inscriptions.extend([ins["id"] for ins in inscriptions])
            offset += limit
        except Exception as e:
            print(f"[WL] Error fetching inscriptions for {address}: {e}")
            return all_inscriptions
    print(f"[WL] Total inscriptions for {address}: {len(all_inscriptions)} inscriptions")
    return all_inscriptions

# ---------- core rebuild logic ----------
def rebuild_used_serials_core():
    added = 0
    total = 0
    for keys in scan_keys(match_pattern="tx:*", count=1000):
        if not keys:
            continue
        for k in keys:
            total += 1
            row = rz_hgetall(k)
            if not isinstance(row, dict):
                continue
            serial = row.get("serial")
            if serial:
                rz_sadd("used_serials", serial)
                added += 1
    return {"scanned_tx_keys": total, "added_to_used_serials": added}

# ---------- routes ----------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/reservation_status', methods=['POST'])
def reservation_status():
    data = request.get_json(force=True) or {}
    rid = data.get('reservationId')
    if not rid:
        return jsonify({"ok": False, "error": "Missing reservationId"}), 400
    resv_data = rz_get_json(f"resv:{rid}")
    if not resv_data:
        return jsonify({"ok": True, "active": False})
    try:
        resv = json.loads(resv_data) if isinstance(resv_data, str) else resv_data
        serial = resv.get("serial")
        wl = resv.get("wl", False)
    except:
        return jsonify({"ok": True, "active": False})
    used = is_serial_used(serial)
    ttl = rz_ttl(f"hold:{serial}")
    return jsonify({"ok": True, "active": True, "serial": serial, "used": used, "ttl": ttl, "wl": wl})

@app.route('/file/<path:fname>')
def serve_original(fname):
    path = os.path.join(SINGLES_DIR, fname)
    return send_file(path, mimetype='image/png', as_attachment=False)

@app.route('/randomize', methods=['POST'])
def randomize_image():
    try:
        fname, serial = pick_available_filename()
        image_info = {
            'background': fname,
            'serial': serial,
            'fightCode': ''
        }
        return jsonify({'imageUrl': f"/file/{fname}", 'imageInfo': image_info})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/reserve_for_image', methods=['POST'])
def reserve_for_image():
    data = request.get_json(force=True)
    fname_wanted = (data or {}).get("filename")
    holder_id = (data or {}).get("holderId") or request.headers.get("X-Client-Id") or request.remote_addr or "anon"
    try:
        fname, serial = pick_available_filename(preferred_fname=fname_wanted)
        ok = try_hold_serial(serial, holder_id, ttl=900)
        if not ok:
            fname, serial = pick_available_filename(preferred_fname=None)
            ok = try_hold_serial(serial, holder_id, ttl=900)
            if not ok:
                raise RuntimeError("Could not reserve any image (race)")
        rid = create_reservation_id(serial, ttl=900, wl=False)
        return jsonify({
            "ok": True,
            "filename": fname,
            "serial": serial,
            "reservationId": rid,
            "expiresAt": int(time.time()) + 900,
            "imageUrl": f"/file/{fname}"
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/supply', methods=['GET'])
def supply():
    try:
        used = rz_scard("used_serials")
        remaining = max(0, TOTAL_SUPPLY - used)
        return jsonify({"remaining": remaining, "total": TOTAL_SUPPLY})
    except Exception as e:
        return jsonify({"remaining": TOTAL_SUPPLY, "total": TOTAL_SUPPLY, "note": str(e)})

@app.route('/prepare_inscription', methods=['POST'])
def prepare_inscription():
    if not APP_FEE_ADDRESS or APP_FEE_SATS <= 0:
        return jsonify({"error": "Server missing APP_FEE_ADDRESS/APP_FEE_SATS"}), 500
    ts = int(time.time())
    payload = f"{APP_FEE_ADDRESS}:{APP_FEE_SATS}:{ts}"
    sig = sign_data(payload)
    return jsonify({
        "appFeeAddress": APP_FEE_ADDRESS,
        "appFee": APP_FEE_SATS,
        "ts": ts,
        "sig": sig,
        "network": "Mainnet" if BITCOIN_NETWORK.lower() == "mainnet" else "Testnet"
    })

@app.route('/prepare_wl_inscription', methods=['POST'])
def prepare_wl_inscription():
    if not APP_FEE_ADDRESS or WL_FEE_SATS <= 0:
        return jsonify({"error": "Server missing APP_FEE_ADDRESS/WL_FEE_SATS"}), 500
    ts = int(time.time())
    payload = f"{APP_FEE_ADDRESS}:{WL_FEE_SATS}:{ts}"
    sig = sign_data(payload)
    return jsonify({
        "appFeeAddress": APP_FEE_ADDRESS,
        "appFee": WL_FEE_SATS,
        "ts": ts,
        "sig": sig,
        "network": "Mainnet" if BITCOIN_NETWORK.lower() == "mainnet" else "Testnet"
    })

@app.route('/check_wl_eligibility', methods=['POST'])
def check_wl_eligibility():
    data = request.get_json(force=True) or {}
    address = data.get('address')
    if not address:
        return jsonify({"ok": False, "error": "Missing address"}), 400
    try:
        # Load whitelist inscriptions
        wl_inscriptions = load_wl_inscriptions()
        if not wl_inscriptions:
            return jsonify({"ok": False, "error": "Failed to load whitelist inscriptions"}), 500
        
        # Fetch wallet inscriptions
        wallet_inscriptions = fetch_wallet_inscriptions(address)
        
        # Check for blacklisted inscriptions
        valid_inscriptions = []
        blacklisted = []
        for ins in wallet_inscriptions:
            if ins in wl_inscriptions:
                if rz_sismember("blacklisted_inscriptions", ins):
                    blacklisted.append(ins)
                else:
                    valid_inscriptions.append(ins)
        print(f"[WL] Address {address}: {len(valid_inscriptions)} valid inscriptions, {len(blacklisted)} blacklisted: {blacklisted[:5]}...")
        
        if not valid_inscriptions:
            return jsonify({"ok": False, "error": "No valid whitelist inscriptions found"})
        
        return jsonify({
            "ok": True,
            "eligible": True,
            "inscriptions": valid_inscriptions
        })
    except Exception as e:
        print(f"[WL] Error in check_wl_eligibility for {address}: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/claim_wl', methods=['POST'])
def claim_wl():
    data = request.get_json(force=True) or {}
    address = data.get('address')
    inscription_id = data.get('inscriptionId')
    holder_id = (data or {}).get("holderId") or request.headers.get("X-Client-Id") or request.remote_addr or "anon"
    
    if not address or not inscription_id:
        return jsonify({"ok": False, "error": "Missing address or inscriptionId"}), 400
    
    try:
        # Verify inscription is in whitelist and not blacklisted
        wl_inscriptions = load_wl_inscriptions()
        if inscription_id not in wl_inscriptions:
            print(f"[WL] Inscription {inscription_id} not in whitelist for {address}")
            return jsonify({"ok": False, "error": "Inscription not in whitelist"}), 400
        if rz_sismember("blacklisted_inscriptions", inscription_id):
            print(f"[WL] Inscription {inscription_id} already blacklisted for {address}")
            return jsonify({"ok": False, "error": "Inscription already used"}), 400
            
        # Verify wallet owns the inscription
        wallet_inscriptions = fetch_wallet_inscriptions(address)
        if inscription_id not in wallet_inscriptions:
            print(f"[WL] Inscription {inscription_id} not found in wallet for {address}")
            return jsonify({"ok": False, "error": "Inscription not found in wallet"}), 400
            
        # Reserve image
        fname, serial = pick_available_filename()
        ok = try_hold_serial(serial, holder_id, ttl=900)
        if not ok:
            fname, serial = pick_available_filename()
            ok = try_hold_serial(serial, holder_id, ttl=900)
            if not ok:
                raise RuntimeError("Could not reserve any image")
                
        
        # Create WL reservation
        rid = create_reservation_id(serial, ttl=900, wl=True)
        
        print(f"[WL] Reserved image {fname} (serial: {serial}) for {address} with reservation {rid}")
        return jsonify({
            "ok": True,
            "filename": fname,
            "serial": serial,
            "reservationId": rid,
            "expiresAt": int(time.time()) + 900,
            "imageUrl": f"/file/{fname}",
            "inscriptionId": inscription_id
        })
    except Exception as e:
        print(f"[WL] Error in claim_wl for {address}: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/verify_and_store', methods=['POST'])
def verify_and_store():
    data = request.get_json(force=True)
    txId = data.get('txId')
    reservationId = data.get('reservationId')
    if not txId:
        return jsonify({"ok": False, "error": "Missing txId"}), 400
    
    resv_data = rz_get_json(f"resv:{reservationId}")
    if not resv_data:
        return jsonify({"ok": False, "error": "Invalid or expired reservation"}), 400
    
    try:
        resv = json.loads(resv_data) if isinstance(resv_data, str) else resv_data
        serial = resv.get("serial")
        wl = resv.get("wl", False)
    except Exception:
        return jsonify({"ok": False, "error": "Invalid reservation data"}), 400
        
    # Verify that transaction pays the fee
    if not tx_pays_app_fee(txId, wl=wl):
        return jsonify({"ok": False, "error": "App fee not detected or insufficient"}), 400
        
    try:
        # Mark serial as used + cleanup
        rz_sadd("used_serials", serial)
        rz_del(f"hold:{serial}")
        rz_del(f"resv:{reservationId}")
        rz_hset_many(f"tx:{txId}", {
            "serial": serial,
            "pngText": json.dumps({"Serial": serial}),
            "wl": "1" if wl else "0"
        })
        print(f"[WL] Verified and stored tx {txId} for serial {serial} (WL: {wl})")

        # === NEW: Blacklist inscription for WL mints ===
        if wl:
            inscription_id = data.get('inscriptionId')
            if inscription_id:
                rz_sadd("blacklisted_inscriptions", inscription_id)
                print(f"[WL] Blacklisted inscription {inscription_id} after verified mint for tx {txId}")
        # ==============================================

    except Exception as e:
        print(f"[WL] Error in verify_and_store for tx {txId}: {e}")

    return jsonify({"ok": True, "txId": txId, "serial": serial, "wl": wl})
        
    return jsonify({"ok": True, "verifiedAt": int(time.time())})

@app.route('/admin/rebuild_used_serials', methods=['GET', 'POST'])
def rebuild_used_serials():
    token = request.headers.get("X-Internal-Token")
    if token != os.environ.get("INTERNAL_TOKEN"):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    res = rebuild_used_serials_core()
    return jsonify({"ok": True, **res})

@app.route('/healthz')
def healthz():
    return "ok", 200

# ---------- Scheduler setup ----------
scheduler = None
if RUN_SCHEDULER:
    try:
        scheduler = BackgroundScheduler(daemon=True)
        scheduler.start()
    except Exception as e:
        pass

if __name__ == '__main__':
    app.run(debug=False)