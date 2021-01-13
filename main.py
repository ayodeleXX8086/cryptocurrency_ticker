from datetime import datetime
from flask import Flask, jsonify, request, make_response
import jwt
import uuid
import requests
from werkzeug.security import generate_password_hash, check_password_hash
import json
from redis_client import Redis
from functools import wraps
app = Flask(__name__)

SECRET_KEY='Th1s1ss3cr3t'
app.config['SECRET_KEY']=SECRET_KEY

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):

       token = None

       if 'x-access-tokens' in request.headers:
          token = request.headers['x-access-tokens']
       if not token:
          return jsonify({'message': 'a valid token is missing'})
       try:
          print(token)
          data = json.loads(Redis.get_value(token))
          if not data:
              return jsonify({'message': 'token is invalid'})
          current_user = json.loads(Redis.get_value(data['username']))
       except:
          return jsonify({'message': 'token is invalid'})
       return f(current_user, *args,  **kwargs)
    return decorator


@app.route("/signup",methods=["POST"])
def sign_up():
    payload = request.json
    if not (payload.get('username') and payload.get('password')):
        return make_response('Please provide a username and password', 400)
    if Redis.get_value(payload['username']):
        return make_response('User already exist', 400)
    hashed_password = generate_password_hash(payload['password'], method='sha256')
    Redis.set_value(payload['username'],json.dumps({"username":payload['username'], 'password':hashed_password}))
    return jsonify({'message': 'registered successfully'})

@app.route("/login",methods=["POST"])
def login():
    user=request.json
    if not (user.get('username') and user.get('password')):
        return make_response('could not verify', 401)
    payload = Redis.get_value(user['username'])
    s_payload = json.loads(payload) if payload else None
    print(s_payload)
    if s_payload and not check_password_hash(s_payload['password'],user['password']):
        return make_response('Not a valid credentials', 401)
    fake_token=str( uuid.uuid4())
    Redis.set_value(fake_token,payload)
    return jsonify({'message':"Successfully login", "token":fake_token})

@app.route("/test")
@token_required
def test(user):
    print(user)
    timestamp=datetime.now().timestamp()
    return jsonify({"timestamp":timestamp})

@app.route("/subscriptions/validpairs")
@token_required
def get_subscription(user):
    pairs = Redis.get_value('pairs')
    if not pairs:
        res = requests.get('http://shapeshift.io/validpairs')
        if res.status_code<300:
            pairs=res.content
            Redis.set_value("pairs",pairs)
    return pairs

@app.route("/subscriptions", methods=["POST"])
@token_required
def subscribe(user):
    payload=request.json
    pairs = Redis.get_value('pairs')
    if not pairs:
        res = requests.get('http://shapeshift.io/validpairs')
        if res.status_code < 300:
            pairs = res.content
            Redis.set_value("pairs", pairs)
        else:
            pairs='[]'
    s_pairs=json.loads(pairs)
    if payload.get('pairs',None) in s_pairs:
        subscribes=user.get('sub',[])
        subscribes.append(payload['pairs'])
        user['sub']=subscribes
        Redis.set_value(user['username'],json.dumps(user))
        return jsonify({"message":"Successs"})
    return make_response('Not a valid pair', 404)



@app.route("/subscriptions/limits")
@token_required
def get_real_time(user):
    result=[]
    for tick in user.get('sub',[]):
        res = requests.get(f'http://shapeshift.io/limit/{tick}')
        if res.status_code<300:
            print(res.content)
            result.append(json.loads(res.content))
    print(result)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)

