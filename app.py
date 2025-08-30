from flask import Flask, render_template, jsonify, request, send_file
import os, random, time, hmac, hashlib, json, re, uuid
import requests

# ---- Scheduler ----
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)

# ========= CONFIG =========
APP_FEE_ADDRESS = os.getenv("APP_FEE_ADDRESS", "bc1p7w28we62hv7vnvm4jcqrn6e8y5y6qfvvuaq8at0jpj8jyq5lymusp5jsvq")
APP_FEE_SATS    = int(os.getenv("APP_FEE_SATS", "600"))     # Public mint fee
WL_FEE_SATS     = int(os.getenv("WL_FEE_SATS", "600"))      # WL fee (adjust to your real value)
APP_SECRET      = os.getenv("APP_SECRET", "local-dev-secret-change-me")
BITCOIN_NETWORK = os.getenv("BITCOIN_NETWORK", "mainnet")   # or "testnet"
INTERNAL_TOKEN  = os.environ.get("INTERNAL_TOKEN", "")

UPSTASH_URL     = os.getenv("UPSTASH_REDIS_REST_URL", "https://game-raptor-60247.upstash.io")
UPSTASH_TOKEN   = os.getenv("UPSTASH_REDIS_REST_TOKEN", "AetXAAIncDFhNWNhODAzMGU4MDc0ZTk4YWY1NDc3YzM0M2RmNjQwNHAxNjAyNDc")
TOTAL_SUPPLY    = int(os.getenv("TOTAL_SUPPLY", "10000"))

# Optional toggle to enable/disable scheduler (default on)
RUN_SCHEDULER   = os.getenv("RUN_SCHEDULER", "1") not in ("0", "false", "False", "")

# Your Vercel scanner endpoint (kept from your original file)
SCAN_URL        = os.getenv("SCAN_URL", "https://nekonekobackendscan.vercel.app/api/scan")

# Path to whitelist file (default under static/Singles)
WL_FILE_PATH    = os.getenv("WL_INSCRIPTIONS_PATH", None)

# ==========================

SERIAL_REGEX = re.compile(r"\b(\d{10})\b")

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

def rz_smembers(key):
    try:
        res = rz_get(f"/smembers/{key}")
        return res if isinstance(res, list) else []
    except Exception:
        return []

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

# ---------- Helpers ----------
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

def tx_pays_app_fee(txid: str, wl: bool=False) -> bool:
    """
    True for unconfirmed or confirmed tx if total outputs to APP_FEE_ADDRESS
    >= required sats (WL or Public).
    """
    try:
        outputs = fetch_tx_outputs(txid)
    except Exception:
        return False
    min_fee = WL_FEE_SATS if wl else APP_FEE_SATS
    total_to_app = sum(o["value"] for o in outputs if o.get("address") == APP_FEE_ADDRESS)
    return total_to_app >= min_fee

def is_serial_used(serial: str) -> bool:
    return rz_sismember("used_serials", serial)

def is_serial_on_hold(serial: str) -> bool:
    return rz_exists(f"hold:{serial}")

def try_hold_serial(serial: str, holder_id: str, ttl=900) -> bool:
    payload = json.dumps({"holder": holder_id, "ts": int(time.time()), "exp": int(time.time()) + ttl})
    return rz_setex_nx(f"hold:{serial}", payload, ttl)

def create_reservation_id(serial: str, ttl=900, wl: bool=False, inscription_id: str=None, address: str=None) -> str:
    """
    Store reservation as JSON so we can distinguish WL vs Public and keep address/inscriptionId.
    Backward compatibility: old code read the value as a plain serial string.
    """
    rid = str(uuid.uuid4())
    payload = {"serial": serial, "wl": bool(wl)}
    if inscription_id:
        payload["inscriptionId"] = inscription_id
    if address:
        payload["address"] = address
    rz_setex(f"resv:{rid}", json.dumps(payload), ttl)
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

# ===== WL JSON loader + wallet ownership =====
def load_wl_inscriptions() -> set:
    """
    Accepts either:
      - [ {"id": "<inscriptionId>"}, ... ]
      - ["<inscriptionId>", ...]
      - {"inscriptions": [...]}
    Returns set[str] of inscription IDs.
    """
    path = WL_FILE_PATH or os.path.join(SINGLES_DIR, "clean_inscriptions.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("inscriptions"), list):
            items = data["inscriptions"]
        elif isinstance(data, list):
            items = data
        else:
            raise ValueError("WL file must be a list or dict with 'inscriptions' list")

        ids = set()
        ignored = 0
        for it in items:
            if isinstance(it, str):
                s = it.strip()
                if s:
                    ids.add(s)
            elif isinstance(it, dict) and isinstance(it.get("id"), str):
                s = it["id"].strip()
                if s:
                    ids.add(s)
            else:
                ignored += 1
        print(f"[WL] Loaded {len(ids)} WL ids (ignored {ignored}) from {path}")
        return ids
    except Exception as e:
        print(f"[WL] Error reading WL at {path}: {e}")
        return set()

HIRO_API_TOKEN = os.getenv("HIRO_API_TOKEN", "")
def fetch_wallet_inscriptions(address: str) -> list[str]:
    """
    Pull all inscriptions owned by the given address via Hiro (paginated).
    """
    headers = {}
    if HIRO_API_TOKEN:
        headers["Authorization"] = f"Bearer {HIRO_API_TOKEN}"

    base = "https://api.hiro.so/ordinals/v1/inscriptions"
    limit = 200
    offset = 0
    out = []
    seen = set()
    try:
        for _ in range(100):  # hard cap
            url = f"{base}?address={address}&limit={limit}&offset={offset}"
            r = requests.get(url, headers=headers, timeout=20)
            if r.status_code >= 400:
                print(f"[WL] Hiro error {r.status_code}: {r.text[:200]}")
                break
            j = r.json() or {}
            results = j.get("results") or []
            if not results:
                break
            new = 0
            for it in results:
                _id = it.get("id")
                if isinstance(_id, str) and _id not in seen:
                    seen.add(_id)
                    out.append(_id)
                    new += 1
            offset += len(results)
            if new == 0:
                break
        print(f"[WL] Wallet {address} has {len(out)} inscriptions (sample {out[:3]})")
        return out
    except Exception as e:
        print(f"[WL] fetch_wallet_inscriptions error for {address}: {e}")
        return []

# ---------- core rebuild logic ----------
def rebuild_used_serials_core():
    """
    Scan tx:* hashes and SADD their 'serial' field into used_serials.
    (Keeps your counter in sync with the scanner.)
    """
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

    resv = rz_get_json(f"/get/resv:{rid}")
    if not resv:
        return jsonify({"ok": True, "active": False})

    serial = None
    wl = False
    try:
        # Support both old (raw serial string) and new JSON payload
        if isinstance(resv, str):
            serial = resv
        else:
            obj = json.loads(resv) if isinstance(resv, str) else resv
            serial = obj.get("serial")
            wl = bool(obj.get("wl", False))
    except Exception:
        serial = str(resv)

    used = is_serial_used(serial) if serial else False
    ttl = rz_ttl(f"hold:{serial}") if serial else -2
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

# ===== WL endpoints =====

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
    address = (data.get('address') or '').strip()
    if not address:
        return jsonify({"ok": False, "error": "Missing address"}), 400
    try:
        wl_ids = load_wl_inscriptions()
        if not wl_ids:
            return jsonify({"ok": False, "error": "Failed to load whitelist inscriptions"}), 500

        wallet_ids = fetch_wallet_inscriptions(address)

        valid, blacklisted = [], []
        for ins in wallet_ids:
            if ins in wl_ids:
                if rz_sismember("blacklisted_inscriptions", ins) or rz_exists(f"temp_blacklist:{address}:{ins}"):
                    blacklisted.append(ins)
                else:
                    valid.append(ins)

        print(f"[WL] Address {address}: valid={len(valid)} blacklisted_or_locked={len(blacklisted)}")
        if not valid:
            return jsonify({"ok": False, "eligible": False, "error": "No valid whitelist inscriptions found"})

        return jsonify({"ok": True, "eligible": True, "inscriptions": valid})
    except Exception as e:
        print(f"[WL] Error in check_wl_eligibility for {address}: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/claim_wl', methods=['POST'])
def claim_wl():
    data = request.get_json(force=True) or {}
    address = (data.get('address') or '').strip()
    inscription_id = (data.get('inscriptionId') or '').strip()
    holder_id = (data.get("holderId") or request.headers.get("X-Client-Id") or request.remote_addr or "anon")

    if not address or not inscription_id:
        return jsonify({"ok": False, "error": "Missing address or inscriptionId"}), 400

    try:
        # Verify inscription is in whitelist and not blacklisted
        wl_inscriptions = load_wl_inscriptions()
        if inscription_id not in wl_inscriptions:
            return jsonify({"ok": False, "error": "Inscription not in whitelist"}), 400
        if rz_sismember("blacklisted_inscriptions", inscription_id):
            return jsonify({"ok": False, "error": "Inscription already used"}), 400

        # Verify wallet owns the inscription
        wallet_inscriptions = fetch_wallet_inscriptions(address)
        if inscription_id not in wallet_inscriptions:
            return jsonify({"ok": False, "error": "Inscription not found in wallet"}), 400

        # Locks (20 min)
        lock_key = f"wl_lock:{address}"
        if rz_exists(lock_key):
            return jsonify({"ok": False, "error": "Another WL mint is in progress. Please wait."}), 429
        temp_blacklist_key = f"temp_blacklist:{address}:{inscription_id}"
        if rz_exists(temp_blacklist_key):
            return jsonify({"ok": False, "error": "Inscription temporarily locked. Please wait."}), 429
        rz_setex(temp_blacklist_key, "locked", 1200)
        rz_setex(lock_key, "locked", 1200)

        # Reserve image (20 min hold)
        fname, serial = pick_available_filename()
        ok = try_hold_serial(serial, holder_id, ttl=1200)
        if not ok:
            fname, serial = pick_available_filename()
            ok = try_hold_serial(serial, holder_id, ttl=1200)
            if not ok:
                rz_del(temp_blacklist_key)
                rz_del(lock_key)
                raise RuntimeError("Could not reserve any image")

        # Create WL reservation + mark as pending for finalizer
        rid = create_reservation_id(serial, ttl=1200, wl=True, inscription_id=inscription_id, address=address)
        rz_setex(f"wl_pending:{rid}", json.dumps({
            "address": address,
            "serial": serial,
            "inscriptionId": inscription_id
        }), 1200)

        print(f"[WL] Reserved {fname} (serial {serial}) for {address} WL rid={rid}")
        return jsonify({
            "ok": True,
            "filename": fname,
            "serial": serial,
            "reservationId": rid,
            "expiresAt": int(time.time()) + 1200,
            "imageUrl": f"/file/{fname}",
            "inscriptionId": inscription_id
        })
    except Exception as e:
        print(f"[WL] Error in claim_wl for {address}: {e}")
        rz_del(f"temp_blacklist:{address}:{inscription_id}")
        rz_del(f"wl_lock:{address}")
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/cancel_wl_reservation', methods=['POST'])
def cancel_wl_reservation():
    data = request.get_json(force=True) or {}
    reservationId = data.get('reservationId')
    filename = data.get('filename')
    address = data.get('address')
    inscription_id = data.get('inscriptionId')
    if not reservationId or not filename or not address:
        return jsonify({"ok": False, "error": "Missing reservationId, filename, or address"}), 400
    try:
        resv_data = rz_get_json(f"resv:{reservationId}")
        if resv_data:
            resv = json.loads(resv_data) if isinstance(resv_data, str) else resv_data
            serial = resv.get("serial")
            rz_del(f"resv:{reservationId}")
            rz_del(f"hold:{serial}")
            rz_del(f"temp_blacklist:{address}:{inscription_id}")
            rz_del(f"wl_lock:{address}")
            rz_del(f"wl_pending:{reservationId}")
            print(f"[WL] Cancelled reservation {reservationId} for serial {serial}")
        return jsonify({"ok": True})
    except Exception as e:
        print(f"[WL] Error in cancel_wl_reservation: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/verify_and_store', methods=['POST'])
def verify_and_store():
    """
    Finalization endpoint called by:
      - client (public flow), or
      - WL finalizer (below) once scanner wrote the serial row.
    For WL, we blacklist the exact reserved inscriptionId.
    """
    data = request.get_json(force=True)
    txId = data.get('txId')
    reservationId = data.get('reservationId')
    body_inscription = data.get('inscriptionId')  # optional (WL prefers this)

    if not txId or not reservationId:
        return jsonify({"ok": False, "error": "Missing txId or reservationId"}), 400

    # Load reservation (JSON)
    resv_data = rz_get_json(f"resv:{reservationId}")
    if not resv_data:
        print(f"[VS] Invalid/expired reservation {reservationId}")
        return jsonify({"ok": False, "error": "Invalid or expired reservation"}), 400

    try:
        resv = json.loads(resv_data) if isinstance(resv_data, str) else resv_data
        serial = resv.get("serial")
        wl = bool(resv.get("wl", False))
        resv_inscription = resv.get("inscriptionId")
        chosen_inscription = body_inscription or resv_inscription
        address = resv.get("address")  # stored at claim time for WL
    except Exception as e:
        print(f"[VS] Bad reservation data for {reservationId}: {e}")
        return jsonify({"ok": False, "error": "Invalid reservation data"}), 400

    # Fee check according to flow
    if not tx_pays_app_fee(txId, wl=wl):
        print(f"[VS] App fee check failed for tx={txId} (WL={wl})")
        return jsonify({"ok": False, "error": "App fee not detected or insufficient"}), 400

    try:
        # Mark serial used & clear holds/reservation
        rz_sadd("used_serials", serial)
        rz_del(f"hold:{serial}")
        rz_del(f"resv:{reservationId}")

        blacklisted_inscription = None
        if wl:
            # Clean WL locks
            if address:
                rz_del(f"wl_lock:{address}")
            rz_del(f"wl_pending:{reservationId}")

            # Deterministic blacklist
            if chosen_inscription:
                rz_sadd("blacklisted_inscriptions", chosen_inscription)
                if address:
                    rz_del(f"temp_blacklist:{address}:{chosen_inscription}")
                blacklisted_inscription = chosen_inscription
                print(f"[VS] WL blacklisted {chosen_inscription} for tx {txId}")

        # Store tx metadata (keeps your scanner-compatible fields)
        rz_hset_many(f"tx:{txId}", {
            "serial": serial,
            "wl": "1" if wl else "0"
        })
        print(f"[VS] Verified tx {txId} serial {serial} (WL={wl}). used_serials={rz_scard('used_serials')}")

        return jsonify({
            "ok": True,
            "txId": txId,
            "serial": serial,
            "wl": wl,
            "blacklistedInscription": blacklisted_inscription
        })
    except Exception as e:
        print(f"[VS] Error in verify_and_store for {txId}: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500

# ---------- Admin helpers ----------
@app.route('/admin/rebuild_used_serials', methods=['GET', 'POST'])
def rebuild_used_serials():
    """
    Rebuild used_serials by scanning tx:* hashes and SADD-ing their 'serial' field.
    Dev helper — protected by internal token.
    """
    try:
        token = request.headers.get("X-Internal-Token")
        if token != os.environ.get("INTERNAL_TOKEN"):
            return jsonify({"ok": False, "error": "unauthorized"}), 401

        res = rebuild_used_serials_core()
        return jsonify({"ok": True, **res})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/admin/wl_debug', methods=['POST'])
def wl_debug():
    data = request.get_json(force=True) or {}
    address = (data.get('address') or '').strip()
    if not address:
        return jsonify({"ok": False, "error": "Missing address"}), 400
    wl_ids = load_wl_inscriptions()
    wallet_ids = fetch_wallet_inscriptions(address)
    wl_set = set(wl_ids)
    inter = [i for i in wallet_ids if i in wl_set]

    return jsonify({
        "ok": True,
        "wl_count": len(wl_ids),
        "wallet_count": len(wallet_ids),
        "intersection_count": len(inter),
        "intersection_sample": inter[:5],
        "wallet_sample": wallet_ids[:5],
    })

# ---------- Health ----------
@app.route('/healthz')
def healthz():
    return "ok", 200

# ---------- Periodic tasks ----------
def periodic_tasks():
    try:
        # 1) Ping the Vercel scanner
        try:
            scan_res = requests.get(SCAN_URL, timeout=25)
            print(f"[periodic] scan {SCAN_URL} -> {scan_res.status_code}")
        except Exception as e:
            print(f"[periodic] scan error: {e}")

        # 2) Rebuild used_serials from scanner rows
        try:
            res = rebuild_used_serials_core()
            print(f"[periodic] rebuild_used_serials_core -> {res}")
        except Exception as e:
            print(f"[periodic] rebuild error: {e}")

    except Exception as e:
        print(f"[periodic] unexpected error: {e}")

def wl_finalize_from_scanner():
    """
    For each pending WL reservation:
      - Look up txids attributed to the buyer address (set buyer:<addr>:txs)
        (requires the one-line addition in the Node scanner).
      - Fallback: scan tx:* and match buyerAddr + serial (heavier).
      - When a tx has the same serial, call /verify_and_store to finalize
        (this increments used_serials and blacklists the reserved inscriptionId).
    """
    for keys in scan_keys(match_pattern="wl_pending:*", count=200):
        for key in keys:
            try:
                info = rz_get_json(key)
                info = json.loads(info) if isinstance(info, str) else (info or {})
                rid = key.split("wl_pending:", 1)[1]
                address = (info.get("address") or "").strip()
                serial  = (info.get("serial") or "").strip()
                insc    = (info.get("inscriptionId") or "").strip()
                if not (rid and address and serial):
                    continue

                # Fast path: txs indexed by buyer address (preferred)
                txids = rz_smembers(f"buyer:{address}:txs")

                # Fallback: scan all tx:* rows for buyerAddr match
                if not txids:
                    for tkeys in scan_keys(match_pattern="tx:*", count=500):
                        for tkey in tkeys:
                            row = rz_hgetall(tkey) or {}
                            if (row.get("buyerAddr") or "") == address:
                                txids.append(tkey.replace("tx:", ""))

                if not txids:
                    continue

                matched = False
                for txid in txids:
                    row = rz_hgetall(f"tx:{txid}") or {}
                    row_serial = (row.get("serial") or "").strip()
                    if row_serial != serial:
                        continue
                    # Double-check fee on commit
                    if not tx_pays_app_fee(txid, wl=True):
                        continue

                    print(f"[WL finalize] match: addr={address} serial={serial} tx={txid}")
                    with app.test_request_context('/verify_and_store', method='POST', json={
                        "txId": txid,
                        "reservationId": rid,
                        "inscriptionId": insc
                    }):
                        resp = verify_and_store()
                        print(f"[WL finalize] verify_and_store -> {resp.status_code} {resp.get_json()}")
                    matched = True
                    break

                # If matched, clear pending (verify_and_store also clears it; this is extra safe)
                if matched:
                    rz_del(key)

            except Exception as e:
                print(f"[WL finalize] error on {key}: {e}")

# ---------- Scheduler setup ----------
scheduler = None
if RUN_SCHEDULER:
    try:
        scheduler = BackgroundScheduler(daemon=True)
        # Prove Redis connectivity (will be 0 if empty)
        _ = rz_scard("used_serials")
        print("[scheduler] redis ok")

        # Run your existing periodic tasks
        scheduler.add_job(periodic_tasks, 'interval', minutes=1, max_instances=1, coalesce=True)

        # WL finalizer (check every 10s)
        scheduler.add_job(wl_finalize_from_scanner, 'interval', seconds=10, max_instances=1, coalesce=True)

        scheduler.start()
        print("[scheduler] started periodic + wl-finalizer")
    except Exception as e:
        print(f"[scheduler] failed to start: {e}")

if __name__ == '__main__':
    app.run(debug=True)
