import os, sys, json
from dotenv import load_dotenv, dotenv_values
from pymongo import MongoClient
from flask import Flask, redirect, request, abort, jsonify
import bcrypt
from datetime import datetime, timedelta
from functools import wraps
import jwt
import uuid

class InvalidAPIUsage(Exception):
    status_code = 400

    def __init__(self, message, status_code=None, payload=None):
        super().__init__()
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv

config = dotenv_values('.env')
DB_URL = config['DB']
jwtKey = config['KEY']

app = Flask(__name__)
client = MongoClient(DB_URL)
salt = bcrypt.gensalt()

decksDB = client['decks']
cardColl = decksDB['cards']
usersDB = client['users']
profiles = usersDB['profiles']

def tokenAuth(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        
        token = None
        #JWT AUTH
        if 'Authorization' in request.headers:
           token = request.headers['Authorization']
        if not token:
            return jsonify({'message': 'a valid token is missing'})
        try:
            data = jwt.decode(token, jwtKey, algorithms=["HS256"])
            currentUser = profiles.find_one({'_id' : data['id']})
            currentUser.pop('password')
            currentUser.pop('_id')
            if None in currentUser:
                return jsonify({'message': 'token is invalid'})
        except:
            return jsonify({'message': 'token is invalid'})
        return f(currentUser, *args, **kwargs)
    return decorator


@app.errorhandler(InvalidAPIUsage)
def api_error(e):
    return jsonify(e.to_dict()), e.status_code

@app.route('/', methods=['GET'])
@tokenAuth
def index(currestUser):
    print("Hello")
    return '{"Message":"Cool"}'

@app.route("/login", methods=['POST'])
def login():

    body = json.loads(request.data)
    username = body['username']
    password = body['password']
    
    if None not in (username, password):
        user = profiles.find_one({'name':username})
        if user is None:
            raise InvalidAPIUsage('Invalid Username')
        pwd = user['password']
        if bcrypt.checkpw(password.encode('utf-8'), pwd):
            token = jwt.encode({
            'id': user['_id'],
            'exp' : datetime.utcnow() + timedelta(minutes = 60)
                }, jwtKey)
            print(user['name'] + " has logged in.")
        
            return jsonify({'token': token})
        else:
            raise InvalidAPIUsage('Invalid Password')
    else:
        raise InvalidAPIUsage('Invalid Parameters')

@app.route("/register", methods=['POST'])
def register():
    body = json.loads(request.data)
    password = body['password']
    name = body['username']
    if None in (name, password):
        InvalidAPIUsage("INVALID JSON FORM")
    user = profiles.find({'name': name})
    if None != user:
        InvalidAPIUsage("PROFILE ALREADY EXISTS")
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    token = str(uuid.uuid4())
    stored_user = {'_id':  token, 'name' : name, 'password' : hashed, 'created_at': datetime.now(), 'all_decks': {'public' : ['Default'], "private" : ['Private']},'public_decks' : [{'name': 'Default'}], 'private_decks' : [{'name': 'Private', 'key': 'test'}]}
    print(stored_user)
    profiles.insert_one(stored_user)

    returnUser = {'name' : name}
    return jsonify(returnUser)
    
@app.route("/decks/list", methods=['GET'])
@tokenAuth
def getDecks(currentUser):
    all_decks = currentUser['all_decks']
    
    print("Getting Decks")
    return jsonify({"decks": all_decks})
    
@app.route("/cards/list", methods=['POST'])
@tokenAuth
def getCards(currentUser):
    body = json.loads(request.data)
    deckNames = body['deckName']
    print(deckNames)
    cards = []
    #come back to
    cardCursor = cardColl.find({"deckName": {"$in": deckNames}})
    for card in cardCursor:
        print(card['cards'])
        cards = cards + card['cards']
    return jsonify({'cards': cards})
    
@app.route('/deck/create', methods=['POST'])
def createDeck():
    print('creating deck')
    body = json.loads(request.data)
  
@app.route('/deck/update', methods=['POST'])
def updateDeck():
    print('creating deck')
    body = json.loads(request.data)




if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000,debug=True)