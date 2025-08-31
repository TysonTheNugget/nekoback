from flask import Flask, render_template, jsonify, request, send_file
import os, random, time, hmac, hashlib, json, re, uuid, urllib.parse
import requests
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)

# ========= CONFIG (env in prod) =========
APP_FEE_ADDRESS = os.getenv("APP_FEE_ADDRESS", "bc1p7w28we62hv7vnvm4jcqrn6e8y5y6qfvvuaq8at0jpj8jyq5lymusp5jsvq")
APP_FEE_SATS    = int(os.getenv("APP_FEE_SATS", "6000"))      # Public mint fee
WL_FEE_SATS     = int(os.getenv("WL_FEE_SATS", "600"))        # WL fee
APP_SECRET      = os.getenv("APP_SECRET", "local-dev-secret-change-me")
BITCOIN_NETWORK = os.getenv("BITCOIN_NETWORK", "mainnet")
INTERNAL_TOKEN  = os.environ.get("INTERNAL_TOKEN", "")
UPSTASH_URL   = os.environ["UPSTASH_REDIS_REST_URL"]
UPSTASH_TOKEN = os.environ["UPSTASH_REDIS_REST_TOKEN"]
TOTAL_SUPPLY    = int(os.getenv("TOTAL_SUPPLY", "10000"))
RUN_SCHEDULER   = os.getenv("RUN_SCHEDULER", "1") not in ("0", "false", "False", "")
HIRO_API_TOKEN  = os.getenv("HIRO_API_TOKEN", "1423e3815899d351c41529064e5b9a52")
SCAN_URL        = "https://nekonekobackendscan.vercel.app/api/scan"
WL_FILE_PATH    = os.getenv("WL_INSCRIPTIONS_PATH", None)
PUBLIC_MINT_KEY = "public_mint_start_ts"
FORCE_OPEN_KEY  = "public_mint_open"
# ========================================

SERIAL_REGEX = re.compile(r"\b(\d{10})\b")

current_directory = os.path.dirname(os.path.abspath(__file__))
SINGLES_DIR = os.path.join(current_directory, 'static', 'Singles')
os.makedirs(SINGLES_DIR, exist_ok=True)


def rz_set(key, value):
    return rz_get(f"/set/{key}/{urllib.parse.quote(str(value))}")

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

# ---------- helpers ----------
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

def create_reservation_id(serial: str, ttl=900, wl=False, inscription_id=None, address=None) -> str:
    rid = str(uuid.uuid4())
    payload = {"serial": serial, "wl": bool(wl)}
    if inscription_id: payload["inscriptionId"] = inscription_id
    if address:        payload["address"] = address
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
        if is_serial_used(serial): continue
        if is_serial_on_hold(serial): continue
        return fname, serial
    raise RuntimeError("No available images to reserve")

# ---------- WL helpers ----------
def load_wl_inscriptions():
    path = WL_FILE_PATH or os.path.join(SINGLES_DIR, 'clean_inscriptions.json')
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("inscriptions"), list):
            items = data["inscriptions"]
        elif isinstance(data, list):
            items = data
        else:
            raise ValueError("clean_inscriptions.json must be list or dict with 'inscriptions'")
        ids = []
        for it in items:
            if isinstance(it, str):
                ids.append(it.strip())
            elif isinstance(it, dict) and isinstance(it.get("id"), str):
                ids.append(it["id"].strip())
        print(f"[WL] Loaded {len(ids)} WL ids from {path}")
        return set(ids)
    except Exception as e:
        print(f"[WL] Error loading WL from {path}: {e}")
        return set()

def fetch_wallet_inscriptions(address: str):
    cache_key = f"inscriptions:{address}"
    cached = rz_get_json(cache_key)
    if cached:
        print(f"[WL] Cache hit for {address}: {len(cached)} inscriptions")
        return cached
    
    headers = {"Authorization": f"Bearer {HIRO_API_TOKEN}"} if HIRO_API_TOKEN else {}
    base = "https://api.hiro.so/ordinals/v1/inscriptions"
    limit = 60
    offset = 0
    out = []
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=2, status_forcelist=[429])
    session.mount('https://', HTTPAdapter(max_retries=retries))
    
    try:
        while True:
            url = f"{base}?address={urllib.parse.quote(address)}&limit={limit}&offset={offset}"
            r = session.get(url, headers=headers, timeout=25)
            if r.status_code == 400 and "limit must be" in (r.text or ""):
                if limit > 60:
                    limit = 60
                    continue
            r.raise_for_status()
            j = r.json() or {}
            results = j.get("results") or []
            if not results:
                break
            for it in results:
                _id = it.get("id")
                if isinstance(_id, str):
                    out.append(_id)
            offset += len(results)
            if offset >= 10000:
                break
            time.sleep(0.5)  # Small delay to avoid rate limits
        print(f"[WL] Wallet {address} has {len(out)} inscriptions (sample {out[:4]})")
        rz_setex(cache_key, json.dumps(out), 3600)  # Cache for 1 hour
        return out
    except Exception as e:
        print(f"[WL] Hiro fetch error for {address}: {e}")
        return out

        
def wl_reconcile_by_counter():
    """
    Fallback: if WL reservation’s serial is already in used_serials, finalize anyway.
    Prefer to find a txId; if not, still blacklist & clean.
    """
    for keys in scan_keys(match_pattern="wl_pending:*", count=200):
        for key in keys:
            try:
                rid = key.split("wl_pending:", 1)[1]
                info = rz_get_json(key)
                info = json.loads(info) if isinstance(info, str) else (info or {})
                address = (info.get("address") or "").strip()
                serial  = (info.get("serial") or "").strip()
                insc    = (info.get("inscriptionId") or "").strip()
                if not (rid and serial and insc):
                    continue

                # Only act if counter says the serial is already used
                if not is_serial_used(serial):
                    continue

                # Try to find a txId from buyer index or fallback scan (nice-to-have)
                txid = None
                try:
                    txids = rz_get(f"/smembers/buyer:{address}:txs") or []
                except Exception:
                    txids = []
                if not isinstance(txids, list):
                    txids = []
                for t in txids:
                    row = rz_hgetall(f"tx:{t}") or {}
                    if (row.get("serial") or "").strip() == serial:
                        txid = t
                        break

                if txid:
                    # Use the standard path so you still get metadata
                    with app.test_request_context('/verify_and_store', method='POST', json={
                        "txId": txid,
                        "reservationId": rid,
                        "inscriptionId": insc
                    }):
                        resp = verify_and_store()
                        print(f"[WL reconcile] serial={serial} used & matched tx={txid} -> {resp.status_code}")
                    rz_del(key)  # extra safe
                else:
                    # No tx found, but counter says used — finalize inline
                    added = rz_sadd("blacklisted_inscriptions", insc)
                    rz_del(f"wl_pending:{rid}")
                    rz_del(f"resv:{rid}")
                    rz_del(f"hold:{serial}")
                    if address:
                        rz_del(f"temp_blacklist:{address}:{insc}")
                        rz_del(f"wl_lock:{address}")
                    print(f"[WL reconcile] serial={serial} used; no tx. Blacklisted {insc} (SADD={added}), cleaned rid={rid}")
            except Exception as e:
                print(f"[WL reconcile] error on {key}: {e}")

# ---------- rebuild counter from scanner ----------
def rebuild_used_serials_core():
    added = 0
    total = 0
    for keys in scan_keys(match_pattern="tx:*", count=1000):
        if not keys: continue
        for k in keys:
            total += 1
            row = rz_hgetall(k)
            if not isinstance(row, dict): continue
            serial = row.get("serial")
            if serial:
                rz_sadd("used_serials", serial)
                added += 1
    return {"scanned_tx_keys": total, "added_to_used_serials": added}
    
def _parse_iso_utc(s: str) -> int:
    """
    Very small ISO parser. Accepts:
      - 'YYYY-MM-DDTHH:MM:SSZ'  (UTC)
      - 'YYYY-MM-DD HH:MM:SS'   (assumed UTC)
      - 'YYYY-MM-DDTHH:MM:SS'   (assumed UTC)
    Returns unix seconds, or raises ValueError.
    """
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1].replace("T", " ")
    else:
        s = s.replace("T", " ")
    # Now s like 'YYYY-MM-DD HH:MM:SS'
    y, m, d = map(int, s[:10].split("-"))
    hh, mm, ss = map(int, s[11:19].split(":"))
    return int(time.mktime((y, m, d, hh, mm, ss, 0, 0, 0))) - time.timezone  # convert to UTC
    
def wl_finalize_from_scanner():
    for keys in scan_keys(match_pattern="wl_pending:*", count=200):
        for key in keys:
            try:
                rid = key.split("wl_pending:", 1)[1]
                info = rz_get_json(key)
                info = json.loads(info) if isinstance(info, str) else (info or {})
                address = (info.get("address") or "").strip()
                serial  = (info.get("serial") or "").strip()
                insc    = (info.get("inscriptionId") or "").strip()
                if not (rid and address and serial):
                    continue

                # Fast path: use scanner’s buyer index
                try:
                    txids = rz_get(f"/smembers/buyer:{address}:txs") or []
                except Exception:
                    txids = []
                if not isinstance(txids, list):
                    txids = []

                # Fallback: scan tx:* by buyerAddr
                if not txids:
                    for tkeys in scan_keys(match_pattern="tx:*", count=500):
                        for tkey in tkeys:
                            row = rz_hgetall(tkey) or {}
                            if (row.get("buyerAddr") or "") == address:
                                txids.append(tkey.replace("tx:", ""))

                if not txids:
                    continue

                for txid in txids:
                    row = rz_hgetall(f"tx:{txid}") or {}
                    if (row.get("serial") or "").strip() != serial:
                        continue
                    if not tx_pays_app_fee(txid, wl=True):
                        continue

                    # Call your existing finalizer endpoint in-process
                    with app.test_request_context('/verify_and_store', method='POST', json={
                        "txId": txid,
                        "reservationId": rid,
                        "inscriptionId": insc
                    }):
                        resp = verify_and_store()
                        print(f"[WL finalize] matched addr={address} serial={serial} tx={txid} -> {resp.status_code}")

                    # Clean pending key (verify_and_store also handles cleanup)
                    rz_del(key)
                    break
            except Exception as e:
                print(f"[WL finalize] error on {key}: {e}")

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
        wl = bool(resv.get("wl", False))
    except:
        return jsonify({"ok": True, "active": False})
    used = is_serial_used(serial)
    ttl = rz_ttl(f"hold:{serial}")
    return jsonify({"ok": True, "active": True, "serial": serial, "used": used, "ttl": ttl, "wl": wl})

@app.route('/file/<path:fname>')
def serve_original(fname):
    path = os.path.join(SINGLES_DIR, fname)
    return send_file(path, mimetype='image/png', as_attachment=False)
    
@app.route('/admin/set_public_mint', methods=['POST'])
def admin_set_public_mint():
    # protect with your INTERNAL_TOKEN
    if request.headers.get("X-Internal-Token") != os.getenv("INTERNAL_TOKEN", ""):
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    data = request.get_json(force=True) or {}
    # Options:
    # 1) {"publicMintOpen": true/false}
    # 2) {"publicMintStartTs": 1736000000}              # absolute unix seconds (UTC)
    # 3) {"hoursFromNow": 72}                           # relative
    # 4) {"isoUtc": "2025-09-02T18:00:00Z"}             # ISO UTC

    # Force open toggle (optional)
    if "publicMintOpen" in data:
        rz_set(FORCE_OPEN_KEY, "1" if data["publicMintOpen"] else "0")

    new_start = None
    if "publicMintStartTs" in data:
        new_start = int(data["publicMintStartTs"])
    elif "hoursFromNow" in data:
        new_start = int(time.time()) + int(data["hoursFromNow"]) * 3600
    elif "isoUtc" in data:
        try:
            new_start = _parse_iso_utc(str(data["isoUtc"]))
        except Exception:
            return jsonify({"ok": False, "error": "invalid isoUtc"}), 400

    if new_start is not None:
        if new_start < 0:
            return jsonify({"ok": False, "error": "invalid start timestamp"}), 400
        rz_set(PUBLIC_MINT_KEY, new_start)

    # Return the updated state
    v = rz_get(f"/get/{PUBLIC_MINT_KEY}")
    start_ts = int(v) if v not in (None, "null", "") else 0
    o = rz_get(f"/get/{FORCE_OPEN_KEY}")
    forced_open = (str(o) == "1")
    return jsonify({"ok": True, "publicMintStartTs": start_ts, "publicMintOpen": forced_open})

@app.route('/randomize', methods=['POST'])
def randomize_image():
    try:
        fname, serial = pick_available_filename()
        image_info = {'background': fname,'serial': serial,'fightCode': ''}
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
            "ok": True,"filename": fname,"serial": serial,"reservationId": rid,
            "expiresAt": int(time.time()) + 900,"imageUrl": f"/file/{fname}"
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
    return jsonify({"error": "Public mint locked"}), 403

# ===== WL endpoints =====

@app.route('/prepare_wl_inscription', methods=['POST'])
def prepare_wl_inscription():
    if not APP_FEE_ADDRESS or WL_FEE_SATS <= 0:
        return jsonify({"error": "Server missing APP_FEE_ADDRESS/WL_FEE_SATS"}), 500
    ts = int(time.time())
    payload = f"{APP_FEE_ADDRESS}:{WL_FEE_SATS}:{ts}"
    sig = sign_data(payload)
    return jsonify({
        "appFeeAddress": APP_FEE_ADDRESS,"appFee": WL_FEE_SATS,"ts": ts,"sig": sig,
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
        wl_ids = load_wl_inscriptions()
        if inscription_id not in wl_ids:
            return jsonify({"ok": False, "error": "Inscription not in whitelist"}), 400
        if rz_sismember("blacklisted_inscriptions", inscription_id):
            return jsonify({"ok": False, "error": "Inscription already used"}), 400
        wallet_ids = fetch_wallet_inscriptions(address)
        if inscription_id not in wallet_ids:
            return jsonify({"ok": False, "error": "Inscription not found in wallet"}), 400
        # place holds
        fname, serial = pick_available_filename()
        ok = try_hold_serial(serial, holder_id, ttl=1200)
        if not ok:
            fname, serial = pick_available_filename()
            ok = try_hold_serial(serial, holder_id, ttl=1200)
            if not ok:
                raise RuntimeError("Could not reserve any image")
        rid = create_reservation_id(serial, ttl=1200, wl=True, inscription_id=inscription_id, address=address)
        rz_setex(f"wl_pending:{rid}", json.dumps({"address": address, "serial": serial, "inscriptionId": inscription_id}), 1200)
        # temp lock the exact inscription so it can't be reused while minting
        rz_setex(f"temp_blacklist:{address}:{inscription_id}", "locked", 60)
        print(f"[WL] Reserved {fname} (serial {serial}) for {address} WL rid={rid}")
        return jsonify({
            "ok": True,"filename": fname,"serial": serial,"reservationId": rid,
            "expiresAt": int(time.time()) + 1200,"imageUrl": f"/file/{fname}",
            "inscriptionId": inscription_id
        })
    except Exception as e:
        print(f"[WL] Error in claim_wl for {address}: {e}")
        rz_del(f"temp_blacklist:{address}:{inscription_id}")
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
            print(f"[WL] Cancelled reservation {reservationId} for serial {serial}")
        return jsonify({"ok": True})
    except Exception as e:
        print(f"[WL] Error in cancel_wl_reservation: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/verify_and_store', methods=['POST'])
def verify_and_store():
    """
    Called by client (public) or WL flow when you have a txId ready.
    - Increments used_serials immediately.
    - For WL, blacklists the *exact* inscription id passed/reserved.
    """
    data = request.get_json(force=True)
    txId = data.get('txId')
    reservationId = data.get('reservationId')
    body_inscription = data.get('inscriptionId')  # preferred for WL

    if not txId or not reservationId:
        return jsonify({"ok": False, "error": "Missing txId or reservationId"}), 400

    # Load reservation
    resv_data = rz_get_json(f"resv:{reservationId}")
    if not resv_data:
        return jsonify({"ok": False, "error": "Invalid or expired reservation"}), 400
    try:
        resv = json.loads(resv_data) if isinstance(resv_data, str) else resv_data
        serial = resv.get("serial")
        wl = bool(resv.get("wl", False))
        resv_inscription = resv.get("inscriptionId")
        chosen_inscription = body_inscription or resv_inscription
        address = resv.get("address")
    except Exception:
        return jsonify({"ok": False, "error": "Invalid reservation data"}), 400

    # Fee check (unconfirmed ok)
    if not tx_pays_app_fee(txId, wl=wl):
        return jsonify({"ok": False, "error": "App fee not detected or insufficient"}), 400

    try:
        # mark used + cleanup
        rz_sadd("used_serials", serial)
        rz_del(f"hold:{serial}")
        rz_del(f"resv:{reservationId}")

        # WL blacklist deterministic
        if wl and chosen_inscription:
            added = rz_sadd("blacklisted_inscriptions", chosen_inscription)
            print(f"[VS] WL blacklisted {chosen_inscription} (SADD={added}) for tx {txId}")
            if address:
                rz_del(f"temp_blacklist:{address}:{chosen_inscription}")

        # record tx meta
        rz_hset_many(f"tx:{txId}", {
            "serial": serial,
            "wl": "1" if wl else "0"
        })
        return jsonify({
            "ok": True,
            "txId": txId,
            "serial": serial,
            "wl": wl,
            "blacklistedInscription": chosen_inscription if wl else None
        })
    except Exception as e:
        print(f"[VS] verify_and_store error: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500

# ---------- Admin ----------
@app.route('/admin/rebuild_used_serials', methods=['GET','POST'])
def rebuild_used_serials():
    token = request.headers.get("X-Internal-Token")
    if token != os.environ.get("INTERNAL_TOKEN"):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    res = rebuild_used_serials_core()
    return jsonify({"ok": True, **res})

@app.route('/healthz')
def healthz():
    return "ok", 200
    
@app.route('/config', methods=['GET'])
def get_config():
    # read current start_ts and optional force flag
    now = int(time.time())
    try:
        v = rz_get(f"/get/{PUBLIC_MINT_KEY}")
        start_ts = int(v) if v not in (None, "null", "") else 0
    except Exception:
        start_ts = 0

    try:
        o = rz_get(f"/get/{FORCE_OPEN_KEY}")
        forced_open = (str(o) == "1")
    except Exception:
        forced_open = False

    public_open = forced_open or (start_ts == 0) or (now >= start_ts)
    return jsonify({
        "now": now,
        "publicMintStartTs": start_ts,
        "publicMintOpen": public_open
    })

# ---------- Periodic: ping scanner + rebuild counter ----------
def ping_scanner_and_rebuild():
    try:
        r = requests.get(SCAN_URL, timeout=20)
        print(f"[scanner] {SCAN_URL} -> {r.status_code}")
    except Exception as e:
        print(f"[scanner] error: {e}")
    try:
        res = rebuild_used_serials_core()
        print(f"[rebuild] {res}")
    except Exception as e:
        print(f"[rebuild] error: {e}")

# ---------- Scheduler setup ----------
scheduler = None
if RUN_SCHEDULER:
    try:
        _ = rz_scard("used_serials")
        scheduler = BackgroundScheduler(daemon=True)

        # ping scanner + rebuild every 10s (keeps counter live)
        scheduler.add_job(ping_scanner_and_rebuild, 'interval', seconds=15, max_instances=1, coalesce=True)

        # WL auto-finalizer (uses buyer:{address}:txs from scanner) every 10s
        scheduler.add_job(wl_finalize_from_scanner, 'interval', seconds=10, max_instances=1, coalesce=True)
        
        scheduler.add_job(wl_reconcile_by_counter, 'interval', seconds=10, max_instances=1, coalesce=True)


        scheduler.start()
        print("[scheduler] started: scan+rebuild+wl-finalizer every 10s")
    except Exception as e:
        print(f"[scheduler] failed to start: {e}")
