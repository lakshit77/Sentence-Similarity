from flask import Flask, jsonify, request, render_template
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import spacy


app = Flask(__name__)
api = Api(app)

#connecting to mongodb server
client = MongoClient("mongodb://db:27017")
# making database name SimilarityDB
db = client.SimilarityDB
#making table name users
users = db['users']


#Function to check is user exist or not
def UserExist(username):
    if users.find({"username": username}).count() == 0:
        return False
    else:
        return True

# function to verify the password enter by user is correct or not.!!


def verifyPw(username, password):
    if not UserExist(username):
        return False

    hashed_pw = users.find({
        "username": username
    })[0]['password']

    if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
        return True
    else:
        return False

# function to count token number left with user.


def countToken(username):
    token = users.find({
        "username": username,
    })[0]['tokens']
    return token


class Register(Resource):
    def post(self):
        #retriving data from json
        # postedData = request.form

        username = request.form['username']
        password = request.form['password']

        #checking user exist or not
        if UserExist(username):
            retJson = {
                "status": 301,
                "msg": "username already exist. Try another username"
            }
            return jsonify(retJson)
        #hash the password
        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        #insert into database
        users.insert({
            "username": username,
            "password": hashed_pw,
            "tokens": 6
        })

        retJson = {
            "status": 200,
            "msg": "you have successfully signed up to API"
        }

        return jsonify(retJson)


class Detect(Resource):
    def post(self):
        # postedData = request.get_json()

        username = request.form['username']
        password = request.form['password']
        text1 = request.form['text 1']
        text2 = request.form['text 2']

        if not UserExist(username):
            retJson = {
                "status": 301,
                "msg": "username doesnt exist"
            }
            return jsonify(retJson)

        correct_pw = verifyPw(username, password)

        if not correct_pw:
            retJson = {
                "status" : 302,
                "msg" : "password is worng"
            }
            return jsonify(retJson)

        num_token = countToken(username)

        if num_token <= 0:
            retJson = {
                "status" : 303,
                "msg" : "out of token"
            }
            return jsonify(retJson)

        #calculate the edit distance
        nlp = spacy.load("./en_core_web_sm/en_core_web_sm-2.1.0")

        text1 = nlp(text1)
        text2 = nlp(text2)

        # Ratio is a number between 0 and 1, 0 being not similar at all and 1 being exactly similar

        ratio = text1.similarity(text2)

        retJson = {
            "status" : 200,
            "similarity" : ratio,
            "msg" : "Score calculated succesfully"
        }
    
        num_token = countToken(username)
        users.update({
            "username" : username,
        },{
            "$set" : {
                "tokens": num_token - 1
            }
        })

        return jsonify(retJson)

class Refill(Resource):
    def post(self):
        postedData = request.get_json()

        username = request.args.get('username', "")
        password = request.args.get('password', "")
        refill_amount = request.args.get('refill', "")
        # refill_amount = postedData['refill']

        if not UserExist(username):
            retJson = {
                "status" : 301,
                "msg" : "invalid username"
            }

            return jsonify(retJson)

        #do not store password over here store in database, i have store over here for learning purpose
        correct_pw = "abc123"
        if not password == correct_pw:
            retJson = {
                "status" : 304,
                "msg" : "invalid password"
            }

            return jsonify(retJson)

        num_token = countToken(username)
        users.update({
            "username" : username
        },{
            "$set" : {
                "tokens" : refill_amount + num_token
            }
        })

        retJson = {
            "status" : 200,
            "msg": "refilled succesfully"
        }

        return jsonify(retJson)


api.add_resource(Register, "/register")
api.add_resource(Detect, "/detect")
api.add_resource(Refill, "/refill")
@app.route("/")
def index():
    return render_template('register.html')

@app.route("/text")
def text():
    return render_template('text.html')

@app.route("/token")
def token():
    return render_template('refill.html')

if __name__ == "__main__":
    app.run(host= "0.0.0.0")
