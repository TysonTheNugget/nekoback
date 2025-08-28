from flask import Flask, render_template, jsonify, request, send_file
import os, random, time, hmac, hashlib, json, re, uuid
import requests

app = Flask(__name__)

# ========= TEST CONFIG (move to env in prod) =========
APP_FEE_ADDRESS = os.getenv("APP_FEE_ADDRESS", "bc1p7w28we62hv7vnvm4jcqrn6e8y5y6qfvvuaq8at0jpj8jyq5lymusp5jsvq")
APP_FEE_SATS    = int(os.getenv("APP_FEE_SATS", "600"))
APP_SECRET      = os.getenv("APP_SECRET", "local-dev-secret-change-me")
BITCOIN_NETWORK = os.getenv("BITCOIN_NETWORK", "mainnet")  # or "testnet"

UPSTASH_URL     = os.getenv("UPSTASH_REDIS_REST_URL", "https://game-raptor-60247.upstash.io")    # e.g. https://xxxx.upstash.io
UPSTASH_TOKEN   = os.getenv("UPSTASH_REDIS_REST_TOKEN", "AetXAAIncDFhNWNhODAzMGU4MDc0ZTk4YWY1NDc3YzM0M2RmNjQwNHAxNjAyNDc")  # Bearer token
TOTAL_SUPPLY    = int(os.getenv("TOTAL_SUPPLY", "10000"))
SERIAL_REGEX    = re.compile(r"\b(\d{10})\b")                 # adjust if your filenames differ
# =====================================================

current_directory = os.path.dirname(os.path.abspath(__file__))
SINGLES_DIR = os.path.join(current_directory, 'static', 'Singles')
os.makedirs(SINGLES_DIR, exist_ok=True)

# ---------- Upstash helpers ----------
def _rz_result(payload):
    # Upstash REST wraps real value in {"result": ...}
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
    # normalize each pipeline item to its .result
    return [ _rz_result(item) for item in data ]

def rz_exists(key):
    res = rz_get(f"/exists/{key}")   # -> 0 or 1
    return int(res) == 1

def rz_sismember(key, member):
    res = rz_get(f"/sismember/{key}/{member}")  # -> 0 or 1
    return int(res) == 1

def rz_sadd(key, member):
    return rz_get(f"/sadd/{key}/{member}")  # -> 0/1

def rz_scard(key):
    res = rz_get(f"/scard/{key}")  # -> integer
    return int(res)

def rz_setex_nx(key, value, ttl_sec):
    # SET key value NX EX ttl (pipeline); returns "OK" or null
    resp = rz_post_pipeline([["SET", key, value, "NX", "EX", str(ttl_sec)]])
    return bool(resp and resp[0] == "OK")

def rz_setex(key, value, ttl_sec):
    return rz_get(f"/set/{key}/{value}?ex={ttl_sec}")

def rz_del(key):
    return rz_get(f"/del/{key}")

def rz_hgetall(key):
    res = rz_get(f"/hgetall/{key}")
    # Upstash usually returns {"field":"value", ...} but can return flat list
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
    """
    Yields lists of keys for SCAN pages.
    Supports these Upstash shapes:
      - {"result": {"cursor":"0","keys":[...]} }
      - {"result": ["0", ["k1","k2"]]}
      - ["0", ["k1","k2"]]
    """
    if not UPSTASH_URL or not UPSTASH_TOKEN:
        raise RuntimeError("Missing Upstash env (URL/TOKEN)")

    cursor = "0"
    headers = {"Authorization": f"Bearer {UPSTASH_TOKEN}"}
    while True:
        url = f"{UPSTASH_URL}/scan/{cursor}?count={count}"
        if match_pattern:
            url += f"&match={match_pattern}"
        r = requests.get(url, headers=headers, timeout=15)
        r.raise_for_status()
        data = r.json()

        # normalize
        if isinstance(data, dict) and "result" in data:
            res = data["result"]
            if isinstance(res, dict):                 # {"cursor": "...", "keys": [...]}
                cursor = str(res.get("cursor", "0"))
                keys = res.get("keys", [])
            elif isinstance(res, list) and len(res) >= 2:  # ["cursor", ["k1","k2"]]
                cursor = str(res[0])
                keys = res[1]
            else:
                raise ValueError(f"Unexpected SCAN result payload: {res}")
        elif isinstance(data, list) and len(data) >= 2:    # ["cursor", ["k1","k2"]]
            cursor = str(data[0])
            keys = data[1]
        else:
            raise ValueError(f"Unexpected SCAN payload: {data}")

        yield keys
        if cursor == "0":
            break

def rz_hset_many(key: str, mapping: dict):
    # Upstash HSET for multiple fields via pipeline
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
    # returns seconds to expire; -2 if key doesn't exist; -1 if no expire
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
    # fallback: strip extension as serial-ish
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

def tx_pays_app_fee(txid: str) -> bool:
    try:
        outputs = fetch_tx_outputs(txid)
    except Exception:
        return False
    total_to_app = sum(o["value"] for o in outputs if o.get("address") == APP_FEE_ADDRESS)
    return total_to_app >= APP_FEE_SATS

def is_serial_used(serial: str) -> bool:
    # permanently consumed (confirmed OR unconfirmed inscription already seen)
    return rz_sismember("used_serials", serial)

def is_serial_on_hold(serial: str) -> bool:
    return rz_exists(f"hold:{serial}")

def try_hold_serial(serial: str, holder_id: str, ttl=900) -> bool:
    payload = json.dumps({"holder": holder_id, "ts": int(time.time()), "exp": int(time.time()) + ttl})
    return rz_setex_nx(f"hold:{serial}", payload, ttl)

def create_reservation_id(serial: str, ttl=900) -> str:
    rid = str(uuid.uuid4())
    rz_setex(f"resv:{rid}", serial, ttl)
    return rid

def pick_available_filename(preferred_fname=None, max_attempts=100):
    """Pick a filename whose serial is neither used nor on hold. If preferred is given, try it first."""
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

    # If reservation still exists, we can retrieve its serial
    serial = rz_get(f"/get/resv:{rid}")
    if not serial:
        # Either expired or already consumed by verify_and_store
        return jsonify({"ok": True, "active": False})

    used = is_serial_used(serial)
    ttl = rz_ttl(f"hold:{serial}")  # how many seconds left on their 15-min hold
    return jsonify({"ok": True, "active": True, "serial": serial, "used": used, "ttl": ttl})

@app.route('/file/<path:fname>')
def serve_original(fname):
    path = os.path.join(SINGLES_DIR, fname)
    return send_file(path, mimetype='image/png', as_attachment=False)

@app.route('/randomize', methods=['POST'])
def randomize_image():
    """Preview only: never shows used or currently-held images."""
    try:
        fname, serial = pick_available_filename()
        full_path = os.path.join(SINGLES_DIR, fname)
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
    """Reserve the currently displayed image for 15 minutes (NX). If sniped, pick another free one."""
    data = request.get_json(force=True)
    fname_wanted = (data or {}).get("filename")
    # holder id can be a lightweight token (session-ish); we generate one if not provided
    holder_id = (data or {}).get("holderId") or request.headers.get("X-Client-Id") or request.remote_addr or "anon"

    try:
        # 1) pick the requested file if still free; else pick a new one
        fname, serial = pick_available_filename(preferred_fname=fname_wanted)
        # 2) try to put a hold with NX+EX
        ok = try_hold_serial(serial, holder_id, ttl=900)
        if not ok:
            # Race condition: pick another
            fname, serial = pick_available_filename(preferred_fname=None)
            ok = try_hold_serial(serial, holder_id, ttl=900)
            if not ok:
                raise RuntimeError("Could not reserve any image (race)")

        # 3) create a short-lived reservation id -> serial
        rid = create_reservation_id(serial, ttl=900)

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
    """Show remaining / total (excluding temp holds)."""
    try:
        used = rz_scard("used_serials")
        remaining = max(0, TOTAL_SUPPLY - used)
        return jsonify({"remaining": remaining, "total": TOTAL_SUPPLY})
    except Exception as e:
        # If Upstash not available, fall back to showing total
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
    
@app.route('/admin/rebuild_used_serials', methods=['GET', 'POST'])
def rebuild_used_serials():
    """
    Rebuild used_serials by scanning tx:* hashes and SADD-ing their 'serial' field.
    Dev helper — do not expose without auth in production.
    """
    try:
        added = 0
        total = 0
        for keys in scan_keys(match_pattern="tx:*", count=1000):
            if not keys:
                continue
            for k in keys:
                total += 1
                row = rz_hgetall(k)  # already result-normalized by your helper
                if not isinstance(row, dict):
                    continue
                serial = row.get("serial")
                if serial:
                    rz_sadd("used_serials", serial)
                    added += 1
        return jsonify({"ok": True, "scanned_tx_keys": total, "added_to_used_serials": added})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/verify_and_store', methods=['POST'])
def verify_and_store():
    data = request.get_json(force=True)
    txId = data.get('txId')
    reservationId = data.get('reservationId')  # we created this when reserving
    if not txId:
        return jsonify({"ok": False, "error": "Missing txId"}), 400

    # 1) Verify the app fee landed to your fee address
    if not tx_pays_app_fee(txId):
        return jsonify({"ok": False, "error": "App fee not detected or insufficient"}), 400

    # 2) If we have a reservation, get the serial we reserved
    serial = None
    if reservationId:
        try:
            serial = rz_get(f"/get/resv:{reservationId}")  # returns string serial (via .result)
        except Exception:
            serial = None

    # 3) Persist immediately: mark serial "used" and also write it into tx:<txId>
    if serial:
        try:
            # permanently remove from pool
            rz_sadd("used_serials", serial)
            # clear the 15-min hold & reservation token
            rz_del(f"hold:{serial}")
            rz_del(f"resv:{reservationId}")

            # >>> THIS is the key line you were missing <<<
            # write serial (and minimal pngText) straight into the tx hash
            # (if the tx hash already exists from the scanner, this just fills the missing fields)
            rz_hset_many(f"tx:{txId}", {
                "serial": serial,
                # optional: give scanners something to parse later if needed
                "pngText": json.dumps({"Serial": serial})
            })
        except Exception as e:
            # don't fail the whole request if the write has a hiccup
            pass

    return jsonify({"ok": True, "verifiedAt": int(time.time())})

if __name__ == '__main__':
    app.run(debug=True)
