from flask import Flask, request, jsonify, session
from flask import Flask, render_template, jsonify
from flask import Flask, request, jsonify
from flask import request
from flask import send_file
import json
import os
import time
import uuid
from uuid import uuid4
import random
import re
import requests
from pymongo import MongoClient
import cloudinary
import cloudinary.uploader
import cloudinary.api
client = MongoClient(os.environ.get('MONGODB_URI'))
current_directory = os.path.dirname(os.path.abspath(__file__))
import cloudinary
from PIL import Image
db = client['usagis']
purchases_receipts = db['purchases_receipts']
usagis_collection = db['usagis']
a = db['a']
collection = db['counter1']

SINGLES_DIR = os.path.join(current_directory, 'static', 'Singles')


          
cloudinary.config( 
  cloud_name = "dt75r44wv", 
  api_key = "323764115449695", 
  api_secret = "VukvSBAUcVc-9lkaAWR2nwHhKhY" 
)

app = Flask(__name__)
app.secret_key = '12338hdf8efh8'
counter = 0

def index():
    fight_code = ""  # Initialize empty fight_code
    return render_template('index.html', fight_code=fight_code)

name_to_char = {
    # First 11 consonants
    'fury.10atk.3def.png': 'P',
    'ghost.7atk.6def.png': 'Q',
    'LeftRight.6atk.6def.png': 'R',
    'LoveStory.9atk.3def.png': 'S',
    'mecha.11atk.1def.png': 'T',
    'rip.9atk.7def.png': 'V',
    'squad.7atk.4def.png': 'W',
    'suingcompanies.7atk.5def.png': 'X',
    'sword.9atk.4def.png': 'Y',
    'uzi.7atk.6def.png': 'Z',
    'winged.5atk.10def.png': 'b',

    # Next 4 vowels
    'body1': 'oo',
    'body2': 'E',
    'body3': 'I',
    'body4': 'A',

    # Next 11 consonants
    'bit.7def.png': 'B',
    'bitballs.5atk.png': 'C',
    'bitship.2atk.2def.png': 'D',
    'bitwarrior.6atk.2def.png': 'F',
    'ice.7def.2atk.png': 'G',
    'ipad.5atk.5def.png': 'H',
    'reaper.5atk.3def.png': 'J',
    'risingbunny.3atk.7def.png': 'K',
    'rock.11def.png': 'L',
    'tcg.8atk.4def.png': 'M',
    'TIA.11atk.png': 'N',

    # Next 7 vowels
    'bunny.250speed.png': 'U',
    'content.220speed.png': 'a',
    'fang.210speed.png': 'e',
    'maniac2.200speed.png': 'ii',
    'open.225speed.png': 'o',
    'sad.215speed.png': 'u',
    'smirk.251speed.png': 'aa',

    # Next 7 consonants
    'Bigeyes.4def.2atk.png': 'c',
    'bushygreens.5atk.20speed.png': 'd',
    'Deadders.3atk.7def.png': 'f',
    'mad.7atk.10speed.png': 'g',
    'Majin.11atk.3def.5speed.png': 'h',
    'serious.12def.png': 'j',
    'sketchy.7atk.7.def.7speed.png': 'k',

    # Remaining vowels (not enough to fill all)
    'UI.60speed.png': 'y',
    'AppleVR.Gains 20 atk but only for the first 3 turns.png': 'ee',
    'BigGlasses.At start of battle if enemy atk is higher decrease their defense by 15. If lower increase this card atk by 7.png': 'i',
    'biggy.decreases own defense by 5 and increases attack by 12 for the rest of battle.png': 'AA',
    'BitWarriorHelm.increase hp by 300 when hp reaches 500 .When paired with bitwarrior increase the atk of this card by 20 on turn 5.png': '7',
    'Blueomb.when attacked enemy loses 1 atk and 1 def.png': 'uu',
    'BlueSunglass.enemy ordinal effect is negated.10def.10atk.png': '@',
    'Glasses.280hp.7def.png': '3',
    'Greenomb.every time this ordinal attacks increase its own atk and def by 1.png': '4',
    'karatekid2.when hp is below 500 this ordinal gains 55 atk.7def.png': 'yy',
    'OOP.on the 3rd turn flip a coin if heads increase atk by 20 if tails decrease def by 10.7atk.5def.20speed.png': '1',
    'Redomb.can attack twice on 4th turn.10atk.10def.png': 'O',
    'X.Each time this ordinal is attacked  10 times next 3 attacks will do 30 more  atk.10def.png': '0'
}



def extract_stats_from_filename(filename):
    stats = {}
    atk_match = re.search(r'(\d+)atk', filename)
    def_match = re.search(r'(\d+)def', filename)
    speed_match = re.search(r'(\d+)speed', filename)
    hp_match = re.search(r'(\d+)hp', filename)
    if atk_match:
        stats['ATK'] = int(atk_match.group(1))
    if def_match:
        stats['DEF'] = int(def_match.group(1))
    if speed_match:
        stats['SPEED'] = int(speed_match.group(1))
    if hp_match:  # New line
        stats['HP'] = int(hp_match.group(1))
    return stats

def extract_effect_from_filename(filename):
    base_name = os.path.splitext(filename)[0]
    parts = base_name.split('.')
    parts.pop(0)
    parts = [part for part in parts if not re.match(r'\d+(atk|def|speed)', part)]
    effect_text = ".".join(parts)
    
    # Debug: Print the effect_text to see if it's extracted correctly
    print("Debug: Extracted Effect Text:", effect_text)
    
    return effect_text

def format_filename_for_display(filename):
    base_name = os.path.splitext(filename)[0]
    stats_parts = re.findall(r'(\.\d+[atk|def|speed]+)', base_name)
    stats_text = ' '.join(['+' + s.lstrip('.') for s in stats_parts])
    formatted_name = re.sub(r'(\.\d+[atk|def|speed]+)', '', base_name).split('.')[0]
    return f"{formatted_name} {stats_text}"

def select_random_image_from_directory(directory, exclude=None):
    return random.choice([f for f in os.listdir(directory) if f.endswith('.png') and f != exclude])

def generate_random_color_background(width, height):
    color = (random.randint(100, 200), random.randint(100, 200), random.randint(100, 200))
    return Image.new('RGB', (width, height), color)

def adjust_transparency(img):
    r, g, b, a = img.split()
    pixels = a.load()
    width, height = a.size
    for x in range(width):
        for y in range(height):
            if 0 < pixels[x, y] < 255:
                pixels[x, y] = 254
    return Image.merge('RGBA', (r, g, b, a))

def combine_images(layers):
    base = layers[0].convert('RGBA')
    for img_path in layers[1:]:
        img = Image.open(img_path).convert('RGBA')
        if 'Layer2' in img_path:
            img = adjust_transparency(img)
        base.paste(img, (0, 0), mask=img)
    return base

import os

import os  # Make sure to import os if it's not already imported

import os  # Make sure to import os at the beginning of your script

# Paste this modified function into your existing code.
def generate_simple_fight_code(background, body, boost, mouth, eyes, face, mapping):
    # Debug: Check the values of the arguments
    print("Debug: Arguments received by generate_simple_fight_code:")
    print(f"Background: {background}, Body: {body}, Boost: {boost}, Mouth: {mouth}, Eyes: {eyes}, Face: {face}")

    # Clean up the paths to match with dictionary keys
    background = os.path.basename(background)
    # For body, it's already a folder name; no need to clean it up
    boost = os.path.basename(boost)
    mouth = os.path.basename(mouth)
    eyes = os.path.basename(eyes)
    face = os.path.basename(face)

    # Debug: Check the cleaned-up values
    print("Debug: Cleaned-up arguments:")
    print(f"Cleaned Background: {background}, Cleaned Body: {body}, Cleaned Boost: {boost}, Cleaned Mouth: {mouth}, Cleaned Eyes: {eyes}, Cleaned Face: {face}")

    # Generate the fight code based on the mapping
    fight_code = ''.join([mapping.get(background, ''),
                      mapping.get(body.lower(), ''),  # Convert to lowercase here
                      mapping.get(boost, ''),
                      mapping.get(mouth, ''),
                      mapping.get(eyes, ''),
                      mapping.get(face, '')])

    # Debug: Check the generated fight code
    print("Debug: Generated Fight Code:", fight_code)

    return fight_code




def get_random_image_from_folder():
    base_dir = SINGLES_DIR  # uses static/Singles inside the app
    selected_img = select_random_image_from_directory(base_dir)
    if not selected_img:
        raise RuntimeError(f"No PNGs found in: {base_dir}")
    full_path = os.path.join(base_dir, selected_img)
    image_info = {
        'background': selected_img,
        'body': '', 'boost': '', 'mouth': '', 'eyes': '', 'face': '',
        'holdings': '', 'atk': 0, 'def': 0, 'speed': 0, 'hp': 0,
        'effect': '', 'fightCode': ''
    }
    return full_path, image_info



@app.before_request
def log_request():
    print('Timestamp:', request.date)
    print('Request Method:', request.method)
    print('Request URL:', request.url)
    print('Request Headers:', request.headers)
    print('---')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/save_to_mongodb', methods=['POST'])
def save_to_mongodb():
    data = request.json
    
    # Save received data to Flask session
    session['image_info'] = data  # Add this line

    try:
        # Remove MongoDB saving from here; we'll do it later
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "failure", "reason": str(e)})


@app.route('/beta')
def beta():
    return render_template('index2.html')


@app.route('/connect')  # Define the route as '/connect'
def connect():
    return render_template('index3.html')  # Render your 'index3.html' file


@app.route('/save_address', methods=['POST'])
def save_address():
    data = request.json
    address = data.get('address', None)
    
    if address:
        try:
            purchases_receipts.collection.insert_one({'userWalletAddress': address})
            return jsonify({'status': 'success'})
        except Exception as e:
            return jsonify({'status': 'failed', 'reason': str(e)})
    else:
        return jsonify({'status': 'failed', 'reason': 'No address provided'})

@app.route('/save_address_and_txid_to_mongodb', methods=['POST'])
def save_address_and_txid_to_mongodb():
    data = request.json

    # Merge this data with existing session data
    if 'image_info' in session:  # Check if the Flask session contains image_info
        session['image_info'].update(data)  # Add the new data
    else:
        session['image_info'] = data  # In case image_info is not set yet

    try:
        # Now, save all the data into MongoDB as a single entry
        usagis_collection.insert_one(session['image_info'])  # Replace your collection name if different
        session.pop('image_info', None)  # Clear the session for next operation
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "failure", "reason": str(e)})

@app.route("/save", methods=["POST"])
def save_text():
    data = request.json
    addressDisplayContent = data.get("addressDisplayContent", "")
    displayAddressContent = data.get("displayAddressContent", "")
    imageInfoContent = data.get("imageInfoContent", "")

    # You could change the way you save data here, but for now, let's keep it simple
    json_data = {
        "addressDisplayContent": addressDisplayContent,
        "displayAddressContent": displayAddressContent,
        "imageInfoContent": imageInfoContent
    }
    a.collection.insert_one(json_data)
    
    return jsonify({"status": "success"})

@app.route('/increment_counter', methods=['POST'])
def increment_counter():
    counter_doc = collection.find_one({"name": "action_counter"})
    if counter_doc:
        new_count = counter_doc['count'] + 1
        collection.update_one({"name": "action_counter"}, {"$set": {"count": new_count}})
    else:
        new_count = 1
        collection.insert_one({"name": "action_counter", "count": new_count})
    return jsonify({"count": new_count})

@app.route('/get_counter', methods=['GET'])
def get_counter():
    counter_doc = collection.find_one({"name": "action_counter"})
    if counter_doc:
        return jsonify({"count": counter_doc['count']})
    else:
        return jsonify({"count": 0})


@app.route('/store_in_database', methods=['POST'])
def store_in_database():
    data = request.get_json()
    txId = data['txId']
    fightCode = data['fightCode']

    # Use the right collection (e.g., `purchases_receipts`, `usagis_collection`, etc.)
    # I'm assuming you want to use 'purchases_receipts' based on its name. Adjust as needed.
    result = purchases_receipts.insert_one({"txId": txId, "fightCode": fightCode})
    
    return jsonify({"status": "success", "objectId": str(result.inserted_id)})

@app.after_request
def after_request(response):
    response.headers["Access-Control-Allow-Origin"] = "*"  # Allow all origins
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

@app.route('/file/<path:fname>')
def serve_original(fname):
    # serve exact bytes (keeps PNG ancillary chunks)
    path = os.path.join(SINGLES_DIR, fname)
    return send_file(path, mimetype='image/png', as_attachment=False)

@app.route('/randomize', methods=['POST'])
def randomize_image():
    try:
        # pick a local file (you already have this function)
        image_path, image_info = get_random_image_from_folder()

        # return a URL that serves the original bytes (no Cloudinary)
        fname = os.path.basename(image_path)
        original_url = f"/file/{fname}"

        return jsonify({
            'imageUrl': original_url,
            'imageInfo': image_info
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
        
if __name__ == '__main__':
    app.run(debug=True)