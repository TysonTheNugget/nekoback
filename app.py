from flask import Flask, render_template, jsonify, request, send_file
import os, random, time, hmac, hashlib, json, re, uuid
import requests
import urllib.parse
from apscheduler.schedulers.background import BackgroundScheduler
import logging
import zlib

# Suppress HTTP logs
logging.getLogger('werkzeug').disabled = True


app = Flask(__name__)
app.logger.disabled = True

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
PUBLIC_MINT_START_TS = int(os.getenv("PUBLIC_MINT_START_TS", "0"))  # epoch seconds; 0 = open now
MEMPOOL_BASE = "https://mempool.space/api"
CONTENT_BASE = "https://api.hiro.so/ordinals/v1/inscriptions"
PNG_SIG = b'\x89PNG\r\n\x1a\n'
WL_INSCRIPTIONS_CACHE = None
WL_INSCRIPTIONS_MTIME = 0
WL_INSCRIPTIONS_LAST_SOURCE = None
INSCRIPTION_ID_RE = re.compile(r'^[0-9a-f]{64}i\d+$', re.I)
PNG_TEXT_KEY_HINT = None


def _extract_id_from_obj(obj: dict) -> str | None:
    """Try common keys, then scan all values for an inscription id."""
    for k in ('id', 'inscription', 'inscriptionId', 'inscription_id', 'inscriptionid'):
        v = obj.get(k)
        if isinstance(v, str):
            s = v.strip()
            if INSCRIPTION_ID_RE.match(s):
                return s
    for v in obj.values():
        if isinstance(v, str):
            s = v.strip()
            if INSCRIPTION_ID_RE.match(s):
                return s
    return None

def _normalize_wl_payload(data) -> set[str]:
    """Accept multiple JSON shapes and normalize to a set of inscription IDs."""
    out: set[str] = set()
    total = 0
    dicts_no_id = 0

    if isinstance(data, list):
        total = len(data)
        for item in data:
            if isinstance(item, str):
                s = item.strip()
                if INSCRIPTION_ID_RE.match(s):
                    out.add(s)
            elif isinstance(item, dict):
                ins = _extract_id_from_obj(item)
                if ins:
                    out.add(ins)
                else:
                    dicts_no_id += 1
            # ignore other types silently

    elif isinstance(data, dict):
        # Case 1: {"inscriptions": [...]}
        if isinstance(data.get("inscriptions"), (list, tuple)):
            return _normalize_wl_payload(data["inscriptions"])

        # Case 2: mapping-like {"<id>": true, ...} or nested objects
        for k, v in data.items():
            total += 1
            if isinstance(k, str) and INSCRIPTION_ID_RE.match(k.strip()):
                out.add(k.strip())
            elif isinstance(v, str) and INSCRIPTION_ID_RE.match(v.strip()):
                out.add(v.strip())
            elif isinstance(v, dict):
                ins = _extract_id_from_obj(v)
                if ins:
                    out.add(ins)
                else:
                    dicts_no_id += 1
            elif isinstance(v, list):
                # Sometimes nested lists under other keys
                out |= _normalize_wl_payload(v)

    else:
        print(f"[WL] Unsupported WL JSON top-level type: {type(data).__name__}")

    print(f"[WL] WL normalize: total_items_scanned={total}, ids_collected={len(out)}, dicts_without_id={dicts_no_id}")
    return out

def load_wl_inscriptions():
    """
    Reads whitelist from static/Singles/clean_inscriptions.json.
    Accepts either:
      - [ {"id": "<inscriptionId>"}, ... ]  (your original format)
      - ["<inscriptionId>", ...]            (also supported)
      - {"inscriptions": [...]}             (also supported)
    Returns: list[str] of inscription IDs.
    """
    json_path = os.path.join(SINGLES_DIR, 'clean_inscriptions.json')
    try:
        exists = os.path.exists(json_path)
        print(f"[WL] Reading WL from {json_path} (exists={exists})")
        if not exists:
            raise FileNotFoundError(json_path)

        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Normalize a few common shapes
        if isinstance(data, dict) and isinstance(data.get("inscriptions"), list):
            items = data["inscriptions"]
        elif isinstance(data, list):
            items = data
        else:
            raise ValueError("clean_inscriptions.json must be a list or a dict with 'inscriptions' list")

        ids = []
        ignored = 0
        for it in items:
            if isinstance(it, str):
                ids.append(it.strip())
            elif isinstance(it, dict) and "id" in it and isinstance(it["id"], str):
                ids.append(it["id"].strip())
            else:
                ignored += 1

        # Basic sanity + log
        ids = [i for i in ids if i]  # drop empties
        print(f"[WL] Loaded {len(ids)} inscriptions from clean_inscriptions.json (ignored {ignored}). Sample: {ids[:3]}")
        return ids
    except Exception as e:
        print(f"[WL] Error loading clean_inscriptions.json at {json_path}: {e}")
        return []

    print("[WL] FAILED to load WL inscriptions from all candidates.")
    if last_err:
        print(f"[WL] Last error: {last_err}")
    return set()
        
def fetch_wallet_inscriptions(address: str) -> list:
    """
    Fetch ALL inscriptions currently held by an address from Hiro API.
    Handles pagination, uses HIRO_API_TOKEN if available, and logs diagnostics.
    """
    base = "https://api.hiro.so/ordinals/v1/inscriptions"
    limit = 200  # max per page (as allowed by API)
    offset = 0
    out = []
    headers = {}
    if HIRO_API_TOKEN:
        headers["Authorization"] = f"Bearer {HIRO_API_TOKEN}"

    try:
        page_idx = 0
        while True:
            url = f"{base}?address={address}&limit={limit}&offset={offset}"
            r = requests.get(url, headers=headers, timeout=20)
            try:
                r.raise_for_status()
            except Exception as e:
                print(f"[WL] Hiro fetch error (status={r.status_code}) for {url}: {e} body={r.text[:300]}")
                break

            j = r.json() or {}
            results = j.get("results") or []
            count = len(results)
            page_idx += 1
            print(f"[WL] Hiro page {page_idx}: got {count} inscriptions (offset={offset})")

            for it in results:
                _id = it.get("id")
                if isinstance(_id, str):
                    out.append(_id)

            if count < limit:
                break
            offset += limit

        print(f"[WL] Total inscriptions fetched for {address}: {len(out)}")
        # Sample for logs
        if out:
            print(f"[WL] Sample ids: {out[:3]}")
        return out
    except Exception as e:
        print(f"[WL] fetch_wallet_inscriptions error for {address}: {e}")
        return []

def get_case_insensitive(text_map: dict, key: str):
    for k in text_map:
        if k.lower() == key.lower():
            return text_map[k]
    return None

def maybe_serial_from_json_values(text_map: dict):
    for v in text_map.values():
        if not isinstance(v, str):
            continue
        trimmed = v.strip()
        if not trimmed:
            continue
        try:
            obj = json.loads(trimmed)
            s = obj.get('serial') or obj.get('Serial') or (obj.get('name') if re.match(r'^[A-Za-z0-9]{10,24}$', str(obj.get('name', ''))) else None)
            if s:
                return str(s)
        except json.JSONDecodeError:
            pass
    return None

def find_alnum_token(s: str):
    if not isinstance(s, str):
        return None
    m = re.search(r'\b[A-Za-z0-9]{10,24}\b', s)
    return m.group(0) if m else None

def parse_png_text(buf: bytes):
    if not buf or len(buf) < 8 or buf[:8] != PNG_SIG:
        return {"ok": False, "text": None}
    text = {}
    off = 8
    while off + 8 <= len(buf):
        chunk_len = int.from_bytes(buf[off:off+4], 'big')
        off += 4
        chunk_type = buf[off:off+4].decode('latin1')
        off += 4
        if off + chunk_len > len(buf):
            break
        data = buf[off:off + chunk_len]
        off += chunk_len
        off += 4  # Skip CRC
        if chunk_type == "tEXt":
            zero_pos = data.find(b'\x00')
            if zero_pos >= 0:
                k = data[:zero_pos].decode('latin1')
                v = data[zero_pos + 1:].decode('latin1')
                text[k] = v
        elif chunk_type == "zTXt":
            zero_pos = data.find(b'\x00')
            if zero_pos >= 0:
                k = data[:zero_pos].decode('latin1')
                comp_method = data[zero_pos + 1:zero_pos + 2]
                comp_data = data[zero_pos + 2:]
                if comp_method == b'\x00':
                    try:
                        v = zlib.decompress(comp_data).decode('utf-8')
                        text[k] = v
                    except zlib.error as e:
                        text[k] = f"<zTXt decompress error: {e}>"
        elif chunk_type == "iTXt":
            parts = data.split(b'\x00', 5)  # keyword\0comp_flag\0comp_method\0lang\0trans\0payload
            if len(parts) == 6:
                k, comp_flag, comp_method, lang, trans, payload = parts
                try:
                    if comp_flag == b'\x01':
                        v = zlib.decompress(payload).decode('utf-8')
                    else:
                        v = payload.decode('utf-8')
                    text[k.decode('latin1')] = v
                except zlib.error as e:
                    text[k.decode('latin1')] = f"<iTXt error: {e}>"
        if chunk_type == "IEND":
            break
    return {"ok": len(text) > 0, "text": text}

def find_png_inscription_id(txid: str, max_index=5):
    for i in range(max_index + 1):
        ins_id = f"{txid}i{i}"
        buf = fetch_inscription_content(ins_id)
        if buf and len(buf) >= 8 and buf[:8] == PNG_SIG:
            return ins_id
    return None

def fetch_inscription_content(inscription_id: str):
    url = f"{CONTENT_BASE}/{inscription_id}/content"
    headers = {
        'Accept': 'application/octet-stream',  # For raw binary
        'Authorization': f'Bearer {HIRO_API_TOKEN}'
    }
    try:
        r = requests.get(url, headers=headers, timeout=15)
        r.raise_for_status()
        return r.content  # Bytes
    except Exception as e:
        print(f"[WL] Inscription content fetch error for {inscription_id}: {e}")
        return None

def safe_get_json(url):
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"[WL] Mempool fetch error: {e}")
        return None

def fetch_mempool_txs(address):
    return safe_get_json(f"{MEMPOOL_BASE}/address/{address}/txs/mempool") or []

def fetch_chain_txs(address, pages=1):
    out = []
    last = None
    for _ in range(pages):
        url = f"{MEMPOOL_BASE}/address/{address}/txs/chain/{last}" if last else f"{MEMPOOL_BASE}/address/{address}/txs"
        page = safe_get_json(url) or []
        if not page:
            break
        out.extend(page)
        if page:
            last = page[-1].get('txid')
    return out

def is_public_mint_open() -> bool:
    try:
        return int(time.time()) >= int(PUBLIC_MINT_START_TS)
    except Exception:
        return True

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
        
def _read_public_mint_start_ts() -> int:
    return int(PUBLIC_MINT_START_TS)

def public_mint_seconds_until_open() -> int:
    try:
        return max(0, int(PUBLIC_MINT_START_TS) - int(time.time()))
    except Exception:
        return 0

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
    r = requests.get(f"{MEMPOOL_BASE}/tx/{txid}", timeout=20)
    r.raise_for_status()
    j = r.json()
    outs = []
    for vout in j.get("vout", []):
        outs.append({
            "address": vout.get("scriptpubkey_address"),
            "value": vout.get("value", 0)
        })
    return outs
    
def fetch_outspends(txid: str):
    return safe_get_json(f"{MEMPOOL_BASE}/tx/{txid}/outspends") or []

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

def create_reservation_id(serial: str, ttl=900, wl=False, inscription_id: str=None) -> str:
    rid = str(uuid.uuid4())
    payload = {"serial": serial, "wl": wl}
    if inscription_id:
        payload["inscriptionId"] = inscription_id
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

# ---------- Whitelist helpers ----------
def poll_wl_mint(reservation_id, filename, address, inscription_id):
    serial = extract_serial_from_filename(filename)
    print(f"[WL] Starting background polling for reservation {reservation_id}, serial {serial}, address {address}, inscription {inscription_id}")
    attempts = 0
    max_attempts = 90 # 900 seconds / 10 seconds
    while attempts < max_attempts:
        try:
            # Fetch unconfirmed + recent confirmed txs from user's wallet
            mempool_txs = fetch_mempool_txs(address)
            chain_txs = fetch_chain_txs(address, pages=2) # Last 50 txs or so
            all_txs = mempool_txs + chain_txs
            print(f"[WL] Fetched {len(all_txs)} txs from wallet {address} (attempt {attempts + 1})")
            for tx in all_txs:
                txid = tx.get('txid')
                if not txid:
                    continue
                # Check if this tx pays the WL fee (using Mempool)
                if not tx_pays_app_fee(txid, wl=True):
                    continue
                # Get outspends to find reveal txids
                outspends = fetch_outspends(txid)
                candidates = []
                for spend in outspends:
                    if spend.get('spent'):
                        reveal_txid = spend.get('txid')
                        if reveal_txid:
                            candidates.append(reveal_txid)
                uniq_candidates = list(set(candidates))
                for rtxid in uniq_candidates:
                    ins_id = find_png_inscription_id(rtxid)
                    if not ins_id:
                        continue
                    buf = fetch_inscription_content(ins_id)
                    if not buf:
                        continue
                    parsed = parse_png_text(buf)
                    if not parsed['ok']:
                        continue
                    text = parsed['text']
                    # Extract serial (like scan.js)
                    extracted_serial = (
                        text.get(PNG_TEXT_KEY_HINT or 'Serial') or
                        get_case_insensitive(text, 'serial') or
                        maybe_serial_from_json_values(text) or
                        (text.get('name') if re.match(r'^[A-Za-z0-9]{10,24}$', str(text.get('name', ''))) else None) or
                        find_alnum_token('\n'.join(f"{k}={v}" for k, v in text.items()))
                    )
                    if extracted_serial == serial:
                        print(f"[WL] Found matching serial {serial} in tx {txid} for reservation {reservation_id}")
                        # Call verify_and_store with updated data
                        data = {
                            "txId": txid,
                            "reservationId": reservation_id,
                            "address": address,
                            "inscriptionId": inscription_id
                        }
                        with app.test_request_context('/verify_and_store', method='POST', json=data):
                            response = verify_and_store()
                            print(f"[WL] verify_and_store response for tx {txid}: {response.get_json()}")
                        rz_del(f"wl_poll:{reservation_id}")
                        return # Done
        except Exception as e:
            print(f"[WL] Error in poll_wl_mint for {reservation_id} (attempt {attempts + 1}): {e}")
        attempts += 1
        time.sleep(10)
    # Timeout cleanup (unchanged)
    print(f"[WL] Polling timed out for reservation {reservation_id}, serial {serial}")
    resv_data = rz_get_json(f"resv:{reservation_id}")
    if resv_data:
        try:
            resv = json.loads(resv_data) if isinstance(resv_data, str) else resv_data
            serial = resv.get("serial")
            rz_del(f"resv:{reservation_id}")
            rz_del(f"hold:{serial}")
            rz_del(f"temp_blacklist:{address}:{inscription_id}")
            rz_del(f"wl_lock:{address}")
            rz_del(f"wl_poll:{reservation_id}")
            print(f"[WL] Cancelled reservation {reservation_id} for serial {serial} due to polling timeout")
        except Exception as e:
            print(f"[WL] Error cleaning up timed out reservation {reservation_id}: {e}")

            
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
    # Block until public mint start
    if not is_public_mint_open():
        return jsonify({
            "ok": False,
            "error": "Public mint not open yet",
            "mintOpensAt": _read_public_mint_start_ts(),        # unix seconds
            "secondsUntilOpen": public_mint_seconds_until_open()
        }), 403

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
    # Block until public mint opens
    if not is_public_mint_open():
        return jsonify({
            "ok": False,
            "error": "Public mint not open yet",
            "mintOpensAt": _read_public_mint_start_ts(),
            "secondsUntilOpen": public_mint_seconds_until_open()
        }), 403

    if not APP_FEE_ADDRESS or APP_FEE_SATS <= 0:
        return jsonify({"ok": False, "error": "Server missing APP_FEE_ADDRESS/APP_FEE_SATS"}), 500

    ts = int(time.time())
    payload = f"{APP_FEE_ADDRESS}:{APP_FEE_SATS}:{ts}"
    sig = sign_data(payload)

    return jsonify({
        "ok": True,
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
        wl_ids = load_wl_inscriptions()
        print(f"[WL] WL list loaded: {len(wl_ids)} ids")

        if not wl_ids:
            print("[WL] WL empty. Ensure clean_inscriptions.json is found & parsed.")
            return jsonify({"ok": False, "error": "Failed to load whitelist inscriptions"}), 500

        wallet_ids = fetch_wallet_inscriptions(address)
        print(f"[WL] Wallet {address} holds {len(wallet_ids)} inscriptions")

        # Partition wallet ids
        valid, blacklisted = [], []
        for ins in wallet_ids:
            if ins in wl_ids:
                if rz_sismember("blacklisted_inscriptions", ins) or rz_exists(f"temp_blacklist:{address}:{ins}"):
                    blacklisted.append(ins)
                else:
                    valid.append(ins)

        print(f"[WL] Address {address}: valid={len(valid)} blacklisted_or_locked={len(blacklisted)}")
        if valid[:3]:
            print(f"[WL]   valid sample: {valid[:3]}")
        if blacklisted[:3]:
            print(f"[WL]   blacklisted sample: {blacklisted[:3]}")

        if not valid:
            return jsonify({"ok": False, "eligible": False, "error": "No valid whitelist inscriptions found"})

        return jsonify({"ok": True, "eligible": True, "inscriptions": valid})
    except Exception as e:
        print(f"[WL] Error in check_wl_eligibility for {address}: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500

# Replace the existing /claim_wl route with this
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
        valid_inscriptions = [
            ins for ins in wallet_inscriptions
            if ins in wl_inscriptions and not rz_sismember("blacklisted_inscriptions", ins)
            and not rz_exists(f"temp_blacklist:{address}:{ins}")
        ]
        if not valid_inscriptions:
            print(f"[WL] No valid inscriptions found for {address}")
            return jsonify({"ok": False, "error": "No valid inscriptions found in wallet"}), 400
        inscription_id = valid_inscriptions[0]  # Select first valid inscription
        
        # Check WL lock
        lock_key = f"wl_lock:{address}"
        if rz_exists(lock_key):
            print(f"[WL] Address {address} is locked for WL mint")
            return jsonify({"ok": False, "error": "Another WL mint is in progress. Please wait."}), 429
        
        # Temporarily blacklist inscription
        temp_blacklist_key = f"temp_blacklist:{address}:{inscription_id}"
        if rz_exists(temp_blacklist_key):
            print(f"[WL] Inscription {inscription_id} temporarily blacklisted for {address}")
            return jsonify({"ok": False, "error": "Inscription temporarily locked. Please wait."}), 429
        rz_setex(temp_blacklist_key, "locked", 900)  # Lock for 15 minutes
        
        # Set WL lock
        rz_setex(lock_key, "locked", 900)  # Lock for 15 minutes
        
        # Reserve image
        fname, serial = pick_available_filename()
        ok = try_hold_serial(serial, holder_id, ttl=900)
        if not ok:
            fname, serial = pick_available_filename()
            ok = try_hold_serial(serial, holder_id, ttl=900)
            if not ok:
                rz_del(temp_blacklist_key)  # Release temp blacklist on failure
                rz_del(lock_key)  # Release WL lock on failure
                raise RuntimeError("Could not reserve any image")
                
        # Create WL reservation
        rid = create_reservation_id(serial, ttl=900, wl=True, inscription_id=inscription_id)
        
        # Schedule background polling
        rz_setex(f"wl_poll:{rid}", json.dumps({
            "filename": fname,
            "address": address,
            "inscriptionId": inscription_id
        }), 900)
        scheduler.add_job(
            poll_wl_mint,
            args=[rid, fname, address, inscription_id],
            id=f"poll_wl_{rid}",
            max_instances=1,
            replace_existing=True
        )
        
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
        rz_del(f"temp_blacklist:{address}:{inscription_id}")
        rz_del(f"wl_lock:{address}")
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/verify_and_store', methods=['POST'])
def verify_and_store():
    data = request.get_json(force=True)
    txId = data.get('txId')
    reservationId = data.get('reservationId')
    address = data.get('address')
    body_inscription = data.get('inscriptionId')  # optional; preferred if present

    if not txId or not reservationId or not address:
        print(f"[WL] Missing data in verify_and_store: txId={txId}, reservationId={reservationId}, address={address}")
        return jsonify({"ok": False, "error": "Missing txId, reservationId, or address"}), 400

    # Load reservation
    resv_data = rz_get_json(f"resv:{reservationId}")
    if not resv_data:
        print(f"[WL] Invalid or expired reservation {reservationId}")
        return jsonify({"ok": False, "error": "Invalid or expired reservation"}), 400

    try:
        resv = json.loads(resv_data) if isinstance(resv_data, str) else resv_data
        serial = resv.get("serial")
        wl = bool(resv.get("wl", False))
        resv_inscription = resv.get("inscriptionId")
        chosen_inscription = body_inscription or resv_inscription  # deterministic if present
    except Exception as e:
        print(f"[WL] Invalid reservation data for {reservationId}: {e}")
        return jsonify({"ok": False, "error": "Invalid reservation data"}), 400

    # Verify app fee according to WL/regular flow
    if not tx_pays_app_fee(txId, wl=wl):
        print(f"[WL] Insufficient fee for tx {txId} (WL={wl})")
        return jsonify({"ok": False, "error": "App fee not detected or insufficient"}), 400

    try:
        # Mark serial used and clear holds/locks
        rz_sadd("used_serials", serial)
        rz_del(f"hold:{serial}")
        rz_del(f"resv:{reservationId}")
        if wl:
            rz_del(f"wl_lock:{address}")  # clear WL address lock if any

        blacklisted_inscription = None

        if wl:
            if chosen_inscription:
                # Deterministic path: blacklist exactly what we reserved/passed
                rz_sadd("blacklisted_inscriptions", chosen_inscription)
                rz_del(f"temp_blacklist:{address}:{chosen_inscription}")
                blacklisted_inscription = chosen_inscription
                print(f"[WL] Blacklisted exact reservation inscription {chosen_inscription} for tx {txId}")
            else:
                # Fallback ONLY for legacy reservations without inscriptionId (can be removed if not needed)
                wl_inscriptions = load_wl_inscriptions()  # must exist in your app
                print(f"[WL] Loaded {len(wl_inscriptions)} WL inscriptions for tx {txId}")
                wallet_inscriptions = fetch_wallet_inscriptions(address)  # must exist in your app
                print(f"[WL] Fetched {len(wallet_inscriptions)} wallet inscriptions for {address} in tx {txId}")
                valid_inscriptions = [
                    ins for ins in wallet_inscriptions
                    if ins in wl_inscriptions and not rz_sismember("blacklisted_inscriptions", ins)
                ]
                print(f"[WL] Found {len(valid_inscriptions)} valid inscriptions for tx {txId}: {valid_inscriptions[:5]}...")
                if valid_inscriptions:
                    blacklisted_inscription = valid_inscriptions[0]
                    rz_sadd("blacklisted_inscriptions", blacklisted_inscription)
                    rz_del(f"temp_blacklist:{address}:{blacklisted_inscription}")
                    print(f"[WL] Blacklisted fallback inscription {blacklisted_inscription} for tx {txId}")
                else:
                    print(f"[WL] No candidate WL inscription found in fallback for {address}")

        # Record tx metadata
        rz_hset_many(f"tx:{txId}", {
            "serial": serial,
            "pngText": json.dumps({"Serial": serial}),
            "wl": "1" if wl else "0"
        })
        print(f"[WL] Verified and stored tx {txId} for serial {serial} (WL={wl})")

        return jsonify({
            "ok": True,
            "txId": txId,
            "serial": serial,
            "wl": wl,
            "blacklistedInscription": blacklisted_inscription
        })
    except Exception as e:
        print(f"[WL] Error in verify_and_store for {txId}: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/admin/wl_debug', methods=['POST'])
def wl_debug():
    data = request.get_json(force=True) or {}
    address = data.get('address', '').strip()
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

@app.route('/check_scanner', methods=['POST'])
def check_scanner():
    data = request.get_json(force=True) or {}
    filename = data.get('filename')
    address = data.get('address')
    if not filename or not address:
        print(f"[WL] Missing data in check_scanner: filename={filename}, address={address}")
        return jsonify({"ok": False, "error": "Missing filename or address"}), 400
    
    try:
        serial = extract_serial_from_filename(filename)
        print(f"[WL] Checking scanner for serial {serial} from filename {filename}")
        for keys in scan_keys(match_pattern="tx:*", count=1000):
            for key in keys:
                row = rz_hgetall(key)
                if not isinstance(row, dict):
                    continue
                row_serial = row.get("serial")
                print(f"[WL] Scanning tx {key} with serial {row_serial}")
                if row_serial == serial:
                    print(f"[WL] Found tx {key} for filename {filename}")
                    return jsonify({"ok": True, "txId": key.replace("tx:", "")})
        print(f"[WL] No tx found for serial {serial} (filename {filename})")
        return jsonify({"ok": False, "error": "No transaction found for filename"})
    except Exception as e:
        print(f"[WL] Error in check_scanner for {filename}: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/cancel_wl_reservation', methods=['POST'])
def cancel_wl_reservation():
    data = request.get_json(force=True) or {}
    reservationId = data.get('reservationId')
    filename = data.get('filename')
    address = data.get('address')
    inscription_id = data.get('inscriptionId')
    if not reservationId or not filename or not address:
        print(f"[WL] Missing data in cancel_wl_reservation: reservationId={reservationId}, filename={filename}, address={address}")
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
            print(f"[WL] Cancelled reservation {reservationId} for serial {serial}")
        return jsonify({"ok": True})
    except Exception as e:
        print(f"[WL] Error in cancel_wl_reservation: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500

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

@app.route('/config', methods=['GET'])
def config():
    return jsonify({
        "now": int(time.time()),
        "publicMintStartTs": int(PUBLIC_MINT_START_TS),
        "publicMintOpen": is_public_mint_open()
    })
    
# Replace the existing scheduler setup with this
scheduler = None
if RUN_SCHEDULER:
    try:
        scheduler = BackgroundScheduler(daemon=True, timezone="UTC")

        # Test Redis connectivity (use a harmless call instead of /ping)
        try:
            _ = rz_scard("used_serials")  # will return 0 if empty; proves connectivity
            print("[WL] Redis connection successful")
        except Exception as e:
            print(f"[WL] Redis connection failed: {e}")
            raise Exception("Cannot start scheduler without Redis connection") from e

        # Resume pending WL polls from Redis
        try:
            resumed = 0
            for keys in scan_keys(match_pattern="wl_poll:*", count=200):
                for key in keys:
                    try:
                        poll_data = rz_get_json(key)
                        data = json.loads(poll_data) if isinstance(poll_data, str) else (poll_data or {})
                        rid = key.split("wl_poll:", 1)[1] if key.startswith("wl_poll:") else None
                        fname = data.get("filename")
                        addr = data.get("address")
                        insc = data.get("inscriptionId")

                        if not (rid and fname and addr and insc):
                            print(f"[WL] Skipping resume for {key} (missing fields)")
                            continue

                        # Ensure we pass inscriptionId into the poller (deterministic blacklist later)
                        scheduler.add_job(
                            poll_wl_mint,
                            args=[rid, fname, addr, insc],
                            id=f"poll_wl_{rid}",
                            max_instances=1,
                            replace_existing=True,
                            coalesce=True,
                            misfire_grace_time=60
                        )
                        resumed += 1
                        print(f"[WL] Resumed polling for reservation {rid}, filename {fname}, address {addr}")
                    except Exception as e:
                        print(f"[WL] Error resuming poll for {key}: {e}")

            scheduler.start()
            print(f"[WL] Scheduler started (resumed {resumed} WL polls, total jobs: {len(scheduler.get_jobs())})")
        except Exception as e:
            print(f"[WL] Error starting scheduler: {e}")
            raise
    except Exception as e:
        print(f"[WL] Failed to initialize scheduler: {e}")