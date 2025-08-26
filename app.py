from flask import Flask, render_template, jsonify, request, send_file
import os, random
from pymongo import MongoClient

app = Flask(__name__)

# Paths
current_directory = os.path.dirname(os.path.abspath(__file__))
SINGLES_DIR = os.path.join(current_directory, 'static', 'Singles')

# Mongo (needed for /store_in_database)
client = MongoClient(os.environ.get('MONGODB_URI'))
db = client['usagis']
purchases_receipts = db['purchases_receipts']

@app.route('/')
def index():
    return render_template('index.html')

def select_random_image_from_directory(directory, exclude=None):
    files = [f for f in os.listdir(directory) if f.endswith('.png') and f != exclude]
    if not files:
        raise RuntimeError(f"No PNGs found in: {directory}")
    return random.choice(files)

def get_random_image_from_folder():
    selected_img = select_random_image_from_directory(SINGLES_DIR)
    full_path = os.path.join(SINGLES_DIR, selected_img)
    image_info = {
        'background': selected_img,
        'body': '', 'boost': '', 'mouth': '', 'eyes': '', 'face': '',
        'holdings': '', 'atk': 0, 'def': 0, 'speed': 0, 'hp': 0,
        'effect': '', 'fightCode': ''
    }
    return full_path, image_info

@app.route('/file/<path:fname>')
def serve_original(fname):
    path = os.path.join(SINGLES_DIR, fname)
    return send_file(path, mimetype='image/png', as_attachment=False)

@app.route('/randomize', methods=['POST'])
def randomize_image():
    image_path, image_info = get_random_image_from_folder()
    fname = os.path.basename(image_path)
    return jsonify({'imageUrl': f"/file/{fname}", 'imageInfo': image_info})

@app.route('/store_in_database', methods=['POST'])
def store_in_database():
    data = request.get_json(force=True)
    txId = data.get('txId')
    fightCode = data.get('fightCode', '')
    result = purchases_receipts.insert_one({**data, "txId": txId, "fightCode": fightCode})
    return jsonify({"status": "success", "objectId": str(result.inserted_id)})

if __name__ == '__main__':
    app.run(debug=True)
