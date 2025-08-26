import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from datetime import datetime, date
import requests
from io import BytesIO
from PIL import ImageTk, Image
import json

class FeeInscriptionsApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Fee Address Inscriptions Viewer")
        self.root.geometry("800x600")

        # Input section
        tk.Label(self.root, text="Enter Fee Address:").pack(pady=5)
        self.address_entry = tk.Entry(self.root, width=60)
        self.address_entry.pack(pady=5)

        # Date input fields
        date_frame = tk.Frame(self.root)
        date_frame.pack(pady=5)
        tk.Label(date_frame, text="From Date (YYYY-MM-DD, optional):").pack(side=tk.LEFT, padx=5)
        self.from_date_entry = tk.Entry(date_frame, width=12)
        self.from_date_entry.pack(side=tk.LEFT, padx=5)
        tk.Label(date_frame, text="To Date (YYYY-MM-DD, optional):").pack(side=tk.LEFT, padx=5)
        self.to_date_entry = tk.Entry(date_frame, width=12)
        self.to_date_entry.pack(side=tk.LEFT, padx=5)

        self.fetch_button = tk.Button(self.root, text="Fetch Inscriptions", command=self.fetch_inscriptions)
        self.fetch_button.pack(pady=5)

        # Buttons for actions
        self.action_frame = tk.Frame(self.root)
        self.action_frame.pack(pady=5)
        self.select_all_button = tk.Button(self.action_frame, text="Select All", command=self.select_all)
        self.select_all_button.pack(side=tk.LEFT, padx=5)
        self.delete_button = tk.Button(self.action_frame, text="Delete Selected", command=self.delete_selected)
        self.delete_button.pack(side=tk.LEFT, padx=5)
        self.save_button = tk.Button(self.action_frame, text="Save Remaining", command=self.save_remaining)
        self.save_button.pack(side=tk.LEFT, padx=5)
        self.open_button = tk.Button(self.action_frame, text="Open Selected Images", command=self.open_selected)
        self.open_button.pack(side=tk.LEFT, padx=5)

        # Scrollable canvas for image grid
        self.canvas = tk.Canvas(self.root)
        self.scrollbar = tk.Scrollbar(self.root, orient="vertical", command=self.canvas.yview)
        self.scroll_frame = tk.Frame(self.canvas)
        self.scroll_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.scroll_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Results text area
        tk.Label(self.root, text="Results (JSON):").pack(pady=5)
        self.results_text = scrolledtext.ScrolledText(self.root, height=10, wrap=tk.WORD)
        self.results_text.pack(fill="x", padx=10, pady=5)

        self.inscription_ids = []
        self.image_labels = []
        self.selected = set()
        self.photo_images = []  # To prevent garbage collection

        self.root.mainloop()

    def fetch_inscriptions(self):
        address = self.address_entry.get().strip()
        if not address:
            messagebox.showerror("Error", "Please enter a valid address.")
            return

        # Get and validate date inputs
        from_date = None
        to_date = None
        try:
            if self.from_date_entry.get():
                from_date = datetime.strptime(self.from_date_entry.get(), "%Y-%m-%d").date()
            if self.to_date_entry.get():
                to_date = datetime.strptime(self.to_date_entry.get(), "%Y-%m-%d").date()
        except ValueError:
            messagebox.showerror("Error", "Invalid date format. Please use YYYY-MM-DD.")
            return

        self.inscription_ids = self.get_inscription_ids_from_fee_address(address, from_date, to_date)
        self.display_images()
        self.results_text.delete('1.0', tk.END)
        self.results_text.insert(tk.END, json.dumps(self.inscription_ids, indent=2))

    def get_inscription_ids_from_fee_address(self, address, from_date=None, to_date=None):
        txs = []
        last_txid = None
        while True:
            if last_txid:
                url = f"https://mempool.space/api/address/{address}/txs/chain/{last_txid}"
            else:
                url = f"https://mempool.space/api/address/{address}/txs"
            try:
                resp = requests.get(url, timeout=10)
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to fetch transactions: {e}")
                break
            if not data:
                break
            txs.extend(data)
            last_txid = data[-1]['txid']

        inscription_ids = set()
        for tx in txs:
            # Filter by date
            tx_time = datetime.fromtimestamp(tx['status']['block_time'] if tx['status']['confirmed'] else int(datetime.now().timestamp()))
            tx_date = tx_time.date()
            if from_date and tx_date < from_date:
                continue
            if to_date and tx_date > to_date:
                continue

            txid = tx['txid']
            outspends_url = f"https://mempool.space/api/tx/{txid}/outspends"
            try:
                resp = requests.get(outspends_url, timeout=10)
                resp.raise_for_status()
                outspends = resp.json()
            except Exception as e:
                print(f"Error fetching outspends for {txid}: {e}")
                continue

            for idx, out in enumerate(outspends):
                if not out['spent']:
                    continue
                out_address = tx['vout'][idx]['scriptpubkey_address']
                if out_address == address:
                    continue  # Skip the fee output itself
                value = tx['vout'][idx]['value']
                if value > 10000:  # Assume change outputs are larger than 10,000 sats
                    continue
                reveal_txid = out['txid']
                inscription_id = f"{reveal_txid}i0"
                inscription_ids.add(inscription_id)

        return sorted(list(inscription_ids))

    def display_images(self):
        for widget in self.scroll_frame.winfo_children():
            widget.destroy()
        self.image_labels = []
        self.selected = set()
        self.photo_images = []

        cols = 5
        row = 0
        col = 0
        for idx, insc_id in enumerate(self.inscription_ids):
            url = f"https://static.unisat.io/content/{insc_id}"
            try:
                resp = requests.get(url, timeout=5)
                resp.raise_for_status()
                img_data = resp.content
                img = Image.open(BytesIO(img_data))
                img = img.resize((100, 100), Image.LANCZOS)
                photo = ImageTk.PhotoImage(img)
                self.photo_images.append(photo)
                label = tk.Label(self.scroll_frame, image=photo, bd=2, relief="raised")
                label.grid(row=row, column=col, padx=5, pady=5)
                label.bind("<Button-1>", lambda e, i=idx: self.toggle_select(i))
                self.image_labels.append(label)
                col += 1
                if col >= cols:
                    col = 0
                    row += 1
            except Exception as e:
                print(f"Error loading image for {insc_id}: {e}")
                label = tk.Label(self.scroll_frame, text="Image Load Failed", bd=2, relief="raised")
                label.grid(row=row, column=col, padx=5, pady=5)
                self.image_labels.append(label)
                col += 1
                if col >= cols:
                    col = 0
                    row += 1

    def toggle_select(self, idx):
        label = self.image_labels[idx]
        if idx in self.selected:
            self.selected.remove(idx)
            label.config(bd=2, bg="SystemButtonFace")
        else:
            self.selected.add(idx)
            label.config(bd=4, bg="red")

    def select_all(self):
        for idx in range(len(self.inscription_ids)):
            self.selected.add(idx)
            self.image_labels[idx].config(bd=4, bg="red")

    def delete_selected(self):
        if not self.selected:
            messagebox.showinfo("Info", "No images selected.")
            return
        if messagebox.askyesno("Confirm", f"Delete {len(self.selected)} selected inscriptions?"):
            selected_list = sorted(list(self.selected), reverse=True)
            for idx in selected_list:
                del self.inscription_ids[idx]
            self.display_images()

    def save_remaining(self):
        if not self.inscription_ids:
            messagebox.showinfo("Info", "No inscriptions to save.")
            return
        file = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if file:
            with open(file, "w") as f:
                json.dump(self.inscription_ids, f, indent=2)
            messagebox.showinfo("Success", "Inscriptions saved successfully.")

    def open_selected(self):
        if not self.selected:
            messagebox.showinfo("Info", "No images selected to open.")
            return
        for idx in self.selected:
            insc_id = self.inscription_ids[idx]
            image_url = f"https://static.unisat.io/content/{insc_id}"
            import webbrowser
            webbrowser.open(image_url)

if __name__ == "__main__":
    FeeInscriptionsApp()