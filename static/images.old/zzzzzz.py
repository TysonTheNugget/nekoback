import tkinter as tk
from tkinter import ttk, messagebox
from PIL import ImageTk, Image
import os
import json

trait_mapping = {
    "2Af": {"name": "bitmatrix", "folder": "background"},
    "C1u": {"name": "brown", "folder": "background"},
    "4Hb": {"name": "dark", "folder": "background"},
    "gYQ": {"name": "darklightblue", "folder": "background"},
    "oSd": {"name": "green1", "folder": "background"},
    "JIB": {"name": "green2", "folder": "background"},
    "Oq0": {"name": "Orange", "folder": "background"},
    "KAF": {"name": "OrangeBitcoins", "folder": "background"},
    "ZKA": {"name": "Pink", "folder": "background"},
    "zMJ": {"name": "waterworld", "folder": "background"},
    "EhA": {"name": "wine", "folder": "background"},
    "HWg": {"name": "3color", "folder": "body"},
    "AeP": {"name": "alicecat", "folder": "body"},
    "dmP": {"name": "alien", "folder": "body"},
    "bqd": {"name": "blocks", "folder": "body"},
    "ywD": {"name": "blue", "folder": "body"},
    "by2": {"name": "cheetah", "folder": "body"},
    "DoK": {"name": "firered", "folder": "body"},
    "RRh": {"name": "gizmo", "folder": "body"},
    "obM": {"name": "gold", "folder": "body"},
    "sbp": {"name": "gray", "folder": "body"},
    "jSq": {"name": "green", "folder": "body"},
    "cgE": {"name": "ironmetalcat3000", "folder": "body"},
    "bHv": {"name": "koda", "folder": "body"},
    "PUk": {"name": "neon", "folder": "body"},
    "T6z": {"name": "opcat", "folder": "body"},
    "It2": {"name": "orange", "folder": "body"},
    "peg": {"name": "panicpurple", "folder": "body"},
    "qA7": {"name": "peach", "folder": "body"},
    "WrU": {"name": "pepe", "folder": "body"},
    "AOS": {"name": "pink", "folder": "body"},
    "qPB": {"name": "puppetbody", "folder": "body"},
    "Jcm": {"name": "purple", "folder": "body"},
    "mD9": {"name": "pussboots", "folder": "body"},
    "K6h": {"name": "redabomination", "folder": "body"},
    "gu3": {"name": "redvelvet", "folder": "body"},
    "xA6": {"name": "squirrel", "folder": "body"},
    "1DQ": {"name": "standing", "folder": "body"},
    "7Zo": {"name": "static", "folder": "body"},
    "9mb": {"name": "tigeruppercut", "folder": "body"},
    "SU3": {"name": "tommy", "folder": "body"},
    "yBH": {"name": "whitepaws", "folder": "body"},
    "GPb": {"name": "wrapped", "folder": "body"},
    "VhW": {"name": "yellow", "folder": "body"},
    "DbO": {"name": "zebracat", "folder": "body"},
    "2KN": {"name": "zombie", "folder": "body"},
    "C8p": {"name": "2006hat", "folder": "hat"},
    "7Ub": {"name": "bluebandana", "folder": "hat"},
    "PmL": {"name": "bluegoose", "folder": "hat"},
    "uZ0": {"name": "btcsnapbacks", "folder": "hat"},
    "G6T": {"name": "btcsnapbacks2", "folder": "hat"},
    "pjW": {"name": "cowboy", "folder": "hat"},
    "xRf": {"name": "diamondearring", "folder": "hat"},
    "2m7": {"name": "duckhat", "folder": "hat"},
    "B5q": {"name": "flowers", "folder": "hat"},
    "zSE": {"name": "gentleman", "folder": "hat"},
    "sbd": {"name": "goldencrown", "folder": "hat"},
    "PdT": {"name": "goldenearring", "folder": "hat"},
    "IVO": {"name": "goosehat", "folder": "hat"},
    "e6b": {"name": "greenbandana", "folder": "hat"},
    "l9i": {"name": "halo", "folder": "hat"},
    "FWw": {"name": "icecrown", "folder": "hat"},
    "uwj": {"name": "inmate", "folder": "hat"},
    "OOh": {"name": "lasergoose", "folder": "hat"},
    "YQl": {"name": "luckycharms", "folder": "hat"},
    "jho": {"name": "nohat", "folder": "hat"},
    "8Nf": {"name": "orangebeanie", "folder": "hat"},
    "hcM": {"name": "ordinalsnapbacks", "folder": "hat"},
    "7y4": {"name": "police", "folder": "hat"},
    "7p4": {"name": "puphat", "folder": "hat"},
    "Fpc": {"name": "puphelm", "folder": "hat"},
    "Kq1": {"name": "redbandana", "folder": "hat"},
    "Jdx": {"name": "robingoose", "folder": "hat"},
    "2Zt": {"name": "safetyhelm", "folder": "hat"},
    "XIv": {"name": "sailor", "folder": "hat"},
    "vnw": {"name": "sheepskinhat", "folder": "hat"},
    "E5x": {"name": "silverearring", "folder": "hat"},
    "1Pa": {"name": "tennisviccors", "folder": "hat"},
    "Tgo": {"name": "visoors", "folder": "hat"},
    "XNU": {"name": "chart", "folder": "traits"},
    "2Jr": {"name": "diamonnecklaxe", "folder": "traits"},
    "FaQ": {"name": "goldenpoop", "folder": "traits"},
    "5FY": {"name": "goldmouse", "folder": "traits"},
    "wgy": {"name": "mouse", "folder": "traits"},
    "0bR": {"name": "notrait", "folder": "traits"},
    "ft8": {"name": "pc", "folder": "traits"},
    "RFu": {"name": "wizzy", "folder": "traits"},
    "NN5": {"name": "xrocket", "folder": "traits"},
    "CRq": {"name": "yarn", "folder": "traits"},
    "YRo": {"name": "3d", "folder": "eyes"},
    "PQa": {"name": "bicolor", "folder": "eyes"},
    "6KW": {"name": "bigsus", "folder": "eyes"},
    "tfj": {"name": "bilnd", "folder": "eyes"},
    "dmL": {"name": "blue", "folder": "eyes"},
    "JMs": {"name": "btceyes", "folder": "eyes"},
    "KUI": {"name": "fedup", "folder": "eyes"},
    "Rfl": {"name": "KOL", "folder": "eyes"},
    "SYv": {"name": "laser1000x", "folder": "eyes"},
    "IC4": {"name": "lazer", "folder": "eyes"},
    "GFJ": {"name": "meninblack", "folder": "eyes"},
    "58n": {"name": "moonyellow", "folder": "eyes"},
    "OMX": {"name": "one-eyed orange", "folder": "eyes"},
    "8qc": {"name": "paletteshades", "folder": "eyes"},
    "fkR": {"name": "plz", "folder": "eyes"},
    "2Zl": {"name": "sorryeyes", "folder": "eyes"},
    "x3n": {"name": "sus", "folder": "eyes"},
    "Cis": {"name": "vr", "folder": "eyes"},
    "hYA": {"name": "wide", "folder": "eyes"},
    "E61": {"name": "wideleft", "folder": "eyes"},
    "IVe": {"name": "wideright", "folder": "eyes"},
    "uBb": {"name": "zombieeyes", "folder": "eyes"}
}

class ImageTraitManager:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Cat Image Trait Manager")
        self.root.geometry("1200x800")  # Reasonable size for grid

        # Predefined categories
        self.categories = ['background', 'body', 'hat', 'traits', 'eyes']

        # Data file for traits
        self.data_file = 'cat_traits.json'

        # Load existing data or initialize
        self.data = self.load_data()

        # Collect all image files in current directory (assuming PNG for pixel art)
        self.image_files = [f for f in os.listdir('.') if f.lower().endswith('.png')]
        self.filtered_files = self.image_files.copy()

        # Populate or update data with traits from codes
        for f in self.image_files:
            code = os.path.splitext(f)[0]
            if f not in self.data:
                self.data[f] = {"name": code, "traits": {}}
            if not self.data[f]["traits"]:  # Populate if empty
                if len(code) % 3 == 0:
                    traits = {}
                    for i in range(0, len(code), 3):
                        subcode = code[i:i+3]
                        if subcode in trait_mapping:
                            t = trait_mapping[subcode]
                            traits[t["folder"]] = t["name"]
                    if len(traits) == len(self.categories):  # Ensure all categories present
                        self.data[f]["traits"] = traits

        # Collect unique trait values per category
        self.trait_values = {cat: set() for cat in self.categories}
        self.collect_trait_values()

        # Pagination settings
        self.page = 0
        self.per_page = 20  # 4 rows x 5 columns grid
        self.upscale_factor = 4  # 32x32 -> 128x128 for better visibility

        # Build the GUI
        self.build_gui()

        self.root.mainloop()

    def load_data(self):
        if os.path.exists(self.data_file):
            with open(self.data_file, 'r') as f:
                return json.load(f)
        return {}

    def save_data(self):
        # Only save non-removed images
        with open(self.data_file, 'w') as f:
            json.dump(self.data, f, indent=4)
        messagebox.showinfo("Saved", "Traits saved to JSON file.")

    def collect_trait_values(self):
        for entry in self.data.values():
            for cat, val in entry["traits"].items():
                if val:
                    self.trait_values[cat].add(val)

    def build_gui(self):
        # Search frame
        search_frame = ttk.Frame(self.root)
        search_frame.pack(fill='x', padx=10, pady=5)

        ttk.Label(search_frame, text="Search by Category:").pack(side='left', padx=5)
        self.search_cat = ttk.Combobox(search_frame, values=self.categories, width=15)
        self.search_cat.pack(side='left', padx=5)

        ttk.Label(search_frame, text="Trait Value:").pack(side='left', padx=5)
        self.search_val = ttk.Entry(search_frame, width=20)
        self.search_val.pack(side='left', padx=5)

        ttk.Button(search_frame, text="Search", command=self.perform_search).pack(side='left', padx=5)
        ttk.Button(search_frame, text="Clear Search", command=self.clear_search).pack(side='left', padx=5)
        ttk.Button(search_frame, text="Save JSON", command=self.save_data).pack(side='right', padx=5)

        # Grid frame for images
        self.grid_frame = ttk.Frame(self.root)
        self.grid_frame.pack(fill='both', expand=True, padx=10, pady=10)

        # Navigation frame
        nav_frame = ttk.Frame(self.root)
        nav_frame.pack(fill='x', padx=10, pady=5)

        ttk.Button(nav_frame, text="Previous Page", command=self.prev_page).pack(side='left')
        ttk.Button(nav_frame, text="Next Page", command=self.next_page).pack(side='left', padx=10)
        self.page_label = ttk.Label(nav_frame, text="Page 1 / 1")
        self.page_label.pack(side='left', padx=10)

        # Initial display
        self.display_page()

    def display_page(self):
        # Clear existing widgets in grid
        for widget in self.grid_frame.winfo_children():
            widget.destroy()

        start = self.page * self.per_page
        end = start + self.per_page
        page_files = self.filtered_files[start:end]

        rows = 4
        cols = 5
        for idx, filename in enumerate(page_files):
            row = idx // cols
            col = idx % cols

            # Frame for each image entry
            img_frame = ttk.Frame(self.grid_frame, borderwidth=2, relief="ridge")
            img_frame.grid(row=row, column=col, padx=10, pady=10, sticky='nsew')

            # Load and upscale image
            try:
                img = Image.open(filename)
                img = img.resize((32 * self.upscale_factor, 32 * self.upscale_factor), Image.NEAREST)
                photo = ImageTk.PhotoImage(img)
                img_frame.photo = photo  # Keep reference
                ttk.Label(img_frame, image=photo).pack()
            except Exception as e:
                ttk.Label(img_frame, text=f"Error loading {filename}").pack()

            # Filename label
            ttk.Label(img_frame, text=filename, wraplength=120).pack()

            # Display traits
            traits = self.data.get(filename, {}).get("traits", {})
            for cat in self.categories:
                val = traits.get(cat, 'None')
                ttk.Label(img_frame, text=f"{cat}: {val}", wraplength=120).pack()

            # Button
            ttk.Button(img_frame, text="Remove", command=lambda f=filename: self.remove_image(f)).pack(pady=2)

        # Update page label
        total_pages = (len(self.filtered_files) // self.per_page) + (1 if len(self.filtered_files) % self.per_page else 0)
        self.page_label.config(text=f"Page {self.page + 1} / {total_pages}")

    def prev_page(self):
        if self.page > 0:
            self.page -= 1
            self.display_page()

    def next_page(self):
        if (self.page + 1) * self.per_page < len(self.filtered_files):
            self.page += 1
            self.display_page()

    def perform_search(self):
        cat = self.search_cat.get()
        val = self.search_val.get().strip().lower()
        if not cat:
            messagebox.showwarning("Search Error", "Select a category.")
            return
        self.filtered_files = [
            f for f in self.image_files
            if f in self.data and self.data[f]["traits"].get(cat, '').lower() == val
        ]
        self.page = 0
        self.display_page()

    def clear_search(self):
        self.filtered_files = self.image_files.copy()
        self.page = 0
        self.display_page()

    def remove_image(self, filename):
        if messagebox.askyesno("Confirm Removal", f"Remove {filename}? This will delete the file and remove from data."):
            try:
                os.remove(filename)
                del self.data[filename]
                self.image_files.remove(filename)
                if filename in self.filtered_files:
                    self.filtered_files.remove(filename)
                self.display_page()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to remove {filename}: {str(e)}")

if __name__ == "__main__":
    ImageTraitManager()