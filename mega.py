import tkinter as tk
from tkinter import ttk, messagebox
import os
import requests
from collections import defaultdict
from pathlib import Path
from urllib.parse import quote
import random

# ========= Configuration =========
SINGLES_DIR = Path(__file__).parent / 'static' / 'Singles'  # Adjust if needed

# Redis (placeholders kept as-is)
UPSTASH_URL = "https://game-raptor-60247.upstash.io"
UPSTASH_TOKEN = "AetXAAIncDFhNWNhODAzMGU4MDc0ZTk4YWY1NDc3YzM0M2RmNjQwNHAxNjAyNDc"

# ========= Traits Map =========
traits_map = {
    '2Af': ('bitmatrix background', 'background'),
    'C1u': ('brown background', 'background'),
    '4Hb': ('dark background', 'background'),
    'gYQ': ('dark light blue background', 'background'),
    'oSd': ('green1 background', 'background'),
    'JIB': ('green2 background', 'background'),
    'Oq0': ('Orange background', 'background'),
    'KAF': ('Orange Bitcoins background', 'background'),
    'ZKA': ('Pink background', 'background'),
    'zMJ': ('waterworld background', 'background'),
    'EhA': ('wine background', 'background'),
    'HWg': ('3color body', 'body'),
    'AeP': ('alicecat body', 'body'),
    'dmP': ('alien body', 'body'),
    'bqd': ('blocks body', 'body'),
    'ywD': ('blue body', 'body'),
    'by2': ('cheetah body', 'body'),
    'DoK': ('fire red body', 'body'),
    'RRh': ('gizmo body', 'body'),
    'obM': ('gold body', 'body'),
    'sbp': ('gray body', 'body'),
    'jSq': ('green body', 'body'),
    'cgE': ('iron metal cat 3000 body', 'body'),
    'bHv': ('koda body', 'body'),
    'PUk': ('neon body', 'body'),
    'T6z': ('op cat body', 'body'),
    'It2': ('orange body', 'body'),
    'peg': ('panic purple body', 'body'),
    'qA7': ('peach body', 'body'),
    'WrU': ('pepe body', 'body'),
    'AOS': ('pink body', 'body'),
    'qPB': ('puppet body', 'body'),
    'Jcm': ('purple body', 'body'),
    'mD9': ('puss boots body', 'body'),
    'K6h': ('red abomination body', 'body'),
    'gu3': ('red velvet body', 'body'),
    'xA6': ('squirrel body', 'body'),
    '1DQ': ('standing body', 'body'),
    '7Zo': ('static body', 'body'),
    '9mb': ('tiger uppercut body', 'body'),
    'SU3': ('tommy body', 'body'),
    'yBH': ('white paws body', 'body'),
    'GPb': ('wrapped body', 'body'),
    'VhW': ('yellow body', 'body'),
    'DbO': ('zebra cat body', 'body'),
    '2KN': ('zombie body', 'body'),
    'C8p': ('2006 hat', 'hat'),
    '7Ub': ('blue bandana hat', 'hat'),
    'PmL': ('blue goose hat', 'hat'),
    'uZ0': ('btc snapback hat', 'hat'),
    'G6T': ('btc snapback s2 hat', 'hat'),
    'pjW': ('cowboy hat', 'hat'),
    'xRf': ('diamond earring hat', 'hat'),
    '2m7': ('duck hat', 'hat'),
    'B5q': ('flower hat', 'hat'),
    'zSE': ('gentleman hat', 'hat'),
    'sbd': ('golden crown hat', 'hat'),
    'PdT': ('golden earring hat', 'hat'),
    'IVO': ('goose hat', 'hat'),
    'e6b': ('green bandana hat', 'hat'),
    'l9i': ('halo hat', 'hat'),
    'FWw': ('ice crown hat', 'hat'),
    'uwj': ('inmate hat', 'hat'),
    'OOh': ('laser goose hat', 'hat'),
    'YQl': ('lucky charms hat', 'hat'),
    'jho': ('no hat', 'hat'),
    '8Nf': ('orange beanie hat', 'hat'),
    'hcM': ('ordinals snapback hat', 'hat'),
    '7y4': ('police hat', 'hat'),
    '7p4': ('pup hat', 'hat'),
    'Fpc': ('pup helm hat', 'hat'),
    'Kq1': ('red bandana hat', 'hat'),
    'Jdx': ('robin goose hat', 'hat'),
    '2Zt': ('safety helm hat', 'hat'),
    'XIv': ('sailor hat', 'hat'),
    'vnw': ('sheepskin hat', 'hat'),
    'E5x': ('silver earring hat', 'hat'),
    '1Pa': ('tennis viccor hat', 'hat'),
    'Tgo': ('visor hat', 'hat'),
    'XNU': ('chart traits', 'traits'),
    '2Jr': ('diamond necklace traits', 'traits'),
    'FaQ': ('golden poop traits', 'traits'),
    '5FY': ('gold mouse traits', 'traits'),
    'wgy': ('mouse traits', 'traits'),
    '0bR': ('no trait traits', 'traits'),
    'ft8': ('pc traits', 'traits'),
    'RFu': ('wizzy traits', 'traits'),
    'NN5': ('x rocket traits', 'traits'),
    'CRq': ('yarn traits', 'traits'),
    'YRo': ('3d eyes', 'eyes'),
    'PQa': ('bicolor eyes', 'eyes'),
    '6KW': ('big sus eyes', 'eyes'),
    'tfj': ('blind eyes', 'eyes'),
    'dmL': ('blue eyes', 'eyes'),
    'JMs': ('btc eyes', 'eyes'),
    'KUI': ('fedup eyes', 'eyes'),
    'Rfl': ('KOL eyes', 'eyes'),
    'SYv': ('laser 1000x eyes', 'eyes'),
    'IC4': ('laser eyes', 'eyes'),
    'GFJ': ('men in black eyes', 'eyes'),
    '58n': ('moonyellow eyes', 'eyes'),
    'OMX': ('one-eyed orange eyes', 'eyes'),
    '8qc': ('palette shades eyes', 'eyes'),
    'fkR': ('plz eyes', 'eyes'),
    '2Zl': ('sorry eyes', 'eyes'),
    'x3n': ('sus eyes', 'eyes'),
    'Cis': ('vr eyes', 'eyes'),
    'hYA': ('wide eyes', 'eyes'),
    'E61': ('wide left eyes', 'eyes'),
    'IVe': ('wide right eyes', 'eyes'),
    'uBb': ('zombie eyes', 'eyes'),
}

CATEGORIES = ['background', 'body', 'hat', 'traits', 'eyes']

# ========= Helpers =========
def rz_get(path):
    try:
        r = requests.get(f"{UPSTASH_URL}{path}",
                         headers={"Authorization": f"Bearer {UPSTASH_TOKEN}"},
                         timeout=30)
        r.raise_for_status()
        data = r.json()
        if isinstance(data, dict) and "result" in data:
            return data["result"]
        return data
    except requests.exceptions.HTTPError as e:
        raise ValueError(f"HTTP {e.response.status_code}: {e.response.text}")
    except Exception as e:
        raise ValueError(f"Connection error: {str(e)}")

def fetch_used_serials():
    used = set()
    cursor = "0"
    key = "used_serials"
    count = "1000"
    while True:
        res = rz_get(f"/sscan/{quote(key)}/{cursor}?count={count}")
        if isinstance(res, list) and len(res) >= 2:
            cursor = str(res[0])
            for m in res[1]:
                used.add(str(m))
            if cursor == "0":
                break
        else:
            break
    return used

def extract_traits(filename):
    base = os.path.splitext(filename)[0]  # serial is entire base (15 chars)
    serial = base
    traits = defaultdict(list)
    if len(base) == 15:
        codes = [base[i:i+3] for i in range(0, 15, 3)]
        for code in codes:
            if code in traits_map:
                name, cat = traits_map[code]
                traits[cat].append(name)
    return serial, traits

# ========= Data State =========
all_unused_files = []         # list of dicts: {filename, serial, traits}
trait_index = {cat: defaultdict(list) for cat in CATEGORIES}  # {cat: {trait_name: [file, ...]}}
used_serials = set()

# ========= Core Logic =========
def scan_unused():
    """Scan Singles dir, fetch used_serials, build list of unused only + trait index."""
    global used_serials, all_unused_files, trait_index
    used_serials = set()
    all_unused_files = []
    trait_index = {cat: defaultdict(list) for cat in CATEGORIES}

    try:
        used_serials = fetch_used_serials()
    except Exception as e:
        messagebox.showerror("Redis Error", f"Failed to fetch used_serials: {e}")
        used_serials = set()

    if not SINGLES_DIR.exists():
        SINGLES_DIR.mkdir(parents=True, exist_ok=True)

    # Iterate files efficiently
    with os.scandir(SINGLES_DIR) as it:
        for entry in it:
            if entry.is_file() and entry.name.lower().endswith(".png"):
                serial, traits = extract_traits(entry.name)
                if serial and (serial not in used_serials):
                    rec = {"filename": entry.name, "serial": serial, "traits": traits}
                    all_unused_files.append(rec)
                    # Build trait index
                    for cat, names in traits.items():
                        for t in names:
                            trait_index[cat][t].append(entry.name)

def refresh_ui_from_filter():
    """Refresh listbox according to selected category/trait."""
    image_list.delete(0, tk.END)
    cat = cat_var.get()
    trait = trait_var.get()

    if trait and cat:
        # Filtered by selected trait
        files = trait_index.get(cat, {}).get(trait, [])
        for fname in sorted(files):
            image_list.insert(tk.END, f"{fname} | Serial: {os.path.splitext(fname)[0]}")
        total_for_trait = len(files)
    else:
        # No trait chosen -> show all unused
        for rec in sorted(all_unused_files, key=lambda r: r["filename"]):
            image_list.insert(tk.END, f"{rec['filename']} | Serial: {rec['serial']}")
        total_for_trait = 0

    # Status / counts
    total_unused = len(all_unused_files)
    if trait and cat:
        status_var.set(f"Unused total: {total_unused} | {cat}: “{trait}” → {total_for_trait}")
    else:
        status_var.set(f"Unused total: {total_unused} | Select a trait to filter")

def on_cat_change(_evt=None):
    """Populate trait list for chosen category and clear current trait selection."""
    cat = cat_var.get()
    trait_combo['values'] = sorted(trait_index.get(cat, {}).keys())
    trait_var.set("")
    refresh_ui_from_filter()

def on_trait_change(_evt=None):
    refresh_ui_from_filter()

def select_all_visible():
    image_list.selection_clear(0, tk.END)
    image_list.selection_set(0, tk.END)

def delete_selected():
    sel = image_list.curselection()
    if not sel:
        messagebox.showwarning("No selection", "No images selected.")
        return
    # Gather filenames from listbox rows (before "| Serial:")
    to_delete = []
    for i in sel:
        row = image_list.get(i)
        fname = row.split("|", 1)[0].strip()
        to_delete.append(fname)

    if not to_delete:
        return

    if not messagebox.askyesno("Confirm", f"Delete {len(to_delete)} files?\nThis cannot be undone."):
        return

    deleted = 0
    for fname in to_delete:
        try:
            os.remove(SINGLES_DIR / fname)
            deleted += 1
        except Exception as e:
            messagebox.showerror("Delete Error", f"Failed to delete {fname}: {e}")

    messagebox.showinfo("Done", f"Deleted {deleted} file(s).")
    do_refresh()

def delete_random_n():
    """Delete a random N from the current trait filter set."""
    cat = cat_var.get()
    trait = trait_var.get()
    if not (cat and trait):
        messagebox.showwarning("Pick a trait", "Choose a category and a trait first.")
        return

    try:
        n = int(random_n_var.get().strip())
        if n <= 0:
            raise ValueError
    except Exception:
        messagebox.showwarning("Invalid number", "Enter a positive integer.")
        return

    candidates = trait_index.get(cat, {}).get(trait, [])
    if not candidates:
        messagebox.showwarning("No files", "No unused files match that trait.")
        return

    if n > len(candidates):
        if not messagebox.askyesno("Fewer available",
                                   f"Only {len(candidates)} available. Delete them all?"):
            return
        n = len(candidates)

    pick = random.sample(candidates, n)

    if not messagebox.askyesno("Confirm",
                               f"Delete {n} file(s) with {cat}: “{trait}”?\nThis cannot be undone."):
        return

    deleted = 0
    for fname in pick:
        try:
            os.remove(SINGLES_DIR / fname)
            deleted += 1
        except Exception as e:
            messagebox.showerror("Delete Error", f"Failed to delete {fname}: {e}")

    messagebox.showinfo("Done", f"Deleted {deleted} file(s).")
    do_refresh()

def do_refresh():
    scan_unused()
    # Rebuild trait dropdown values if category already chosen
    if cat_var.get():
        trait_combo['values'] = sorted(trait_index.get(cat_var.get(), {}).keys())
    refresh_ui_from_filter()

# ========= UI =========
root = tk.Tk()
root.title("Neko — Unused Serials Only")
root.geometry("1100x700")

# Top controls
top = ttk.Frame(root)
top.pack(fill=tk.X, padx=10, pady=8)

ttk.Label(top, text="Category:").pack(side=tk.LEFT)
cat_var = tk.StringVar()
cat_combo = ttk.Combobox(top, textvariable=cat_var, state="readonly", width=16,
                         values=CATEGORIES)
cat_combo.pack(side=tk.LEFT, padx=6)
cat_combo.bind("<<ComboboxSelected>>", on_cat_change)

ttk.Label(top, text="Trait:").pack(side=tk.LEFT, padx=(10,0))
trait_var = tk.StringVar()
trait_combo = ttk.Combobox(top, textvariable=trait_var, state="readonly", width=28, values=[])
trait_combo.pack(side=tk.LEFT, padx=6)
trait_combo.bind("<<ComboboxSelected>>", on_trait_change)

ttk.Button(top, text="Refresh", command=do_refresh).pack(side=tk.RIGHT)

# Status
status_var = tk.StringVar(value="Loading…")
status_bar = ttk.Label(root, textvariable=status_var, anchor="w")
status_bar.pack(fill=tk.X, padx=10)

# Center list
center = ttk.Frame(root)
center.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

image_list = tk.Listbox(center, selectmode=tk.EXTENDED, font=("Arial", 9))
image_list_scroll = ttk.Scrollbar(center, orient="vertical", command=image_list.yview)
image_list.configure(yscrollcommand=image_list_scroll.set)
image_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
image_list_scroll.pack(side=tk.LEFT, fill=tk.Y)

# Actions
actions = ttk.Frame(root)
actions.pack(fill=tk.X, padx=10, pady=8)

ttk.Button(actions, text="Select All Visible", command=select_all_visible).pack(side=tk.LEFT)
ttk.Button(actions, text="Delete Selected", command=delete_selected).pack(side=tk.LEFT, padx=6)

ttk.Label(actions, text="Delete random N from selected trait:").pack(side=tk.LEFT, padx=(20,4))
random_n_var = tk.StringVar(value="10")
random_n_entry = ttk.Entry(actions, textvariable=random_n_var, width=8)
random_n_entry.pack(side=tk.LEFT)
ttk.Button(actions, text="Delete Random N", command=delete_random_n).pack(side=tk.LEFT, padx=6)

# Initial load (unused only)
do_refresh()

root.mainloop()
