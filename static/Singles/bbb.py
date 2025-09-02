import json
import os
from pathlib import Path

def extract_unique_ids(data):
    seen = set()
    ids = []

    def add_id(_id: str):
        if not isinstance(_id, str):
            return
        _id = _id.strip()
        if _id and _id not in seen:
            seen.add(_id)
            ids.append(_id)

    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                add_id(item["id"])
            elif isinstance(item, str):
                add_id(item)
    elif isinstance(data, dict) and isinstance(data.get("inscriptions"), list):
        for item in data["inscriptions"]:
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                add_id(item["id"])
            elif isinstance(item, str):
                add_id(item)
    return ids

def main():
    # find file in same folder
    folder = Path(__file__).parent
    path = folder / "clean_inscriptions.json"
    if not path.exists():
        print(f"❌ File not found: {path}")
        return

    # read
    with open(path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except Exception as e:
            print(f"❌ Failed to parse JSON: {e}")
            return

    # extract IDs
    ids = extract_unique_ids(data)
    if not ids:
        print("❌ No IDs found.")
        return

    # backup original
    backup_path = path.with_suffix(".json.bak")
    os.replace(path, backup_path)
    print(f"✅ Backup saved at {backup_path}")

    # write cleaned
    with open(path, "w", encoding="utf-8") as f:
        json.dump(ids, f, ensure_ascii=False, indent=2)
    print(f"✅ Normalized {len(ids)} unique IDs written to {path}")

if __name__ == "__main__":
    main()
