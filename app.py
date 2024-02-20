import json
import time
from flask import Flask, Request, make_response, jsonify, request
import os
import argparse
from urllib.parse import parse_qs
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.sql import func

parser = argparse.ArgumentParser()
parser.add_argument('--port', type=int, default=5000)
parser.add_argument('--debug', action='store_true')

args, _ = parser.parse_known_args()

app = Flask(__name__)

class Base(DeclarativeBase):
  pass
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///cardwarskingdom.db"
db = SQLAlchemy(model_class=Base)
db.init_app(app)

maintenance = False

@app.route("/static/version.txt")
def PersistVersion():
    #create version.txt and android_version.txt if they don't exist
	if not os.path.exists("data/persist/version.txt"):
		with open("data/persist/version.txt", "w") as f:
			f.write("1.0.0")
	if not os.path.exists("data/persist/android_version.txt"):
		with open("data/persist/android_version.txt", "w") as f:
			f.write("1.0.0")
    
	with open("data/persist/version.txt", "r") as f:
		pc_version = f.read()
	with open("data/persist/android_version.txt", "r") as f:
		android_version = f.read()
  
	data = {
		"maintenance_mode": "yes" if maintenance else "no",
		"message": "Card Wars Kingdom is currently undergoing maintenance.\n\nPlease try again later.",
		"icon": "",
		"clickable": "yes",
		"android_version": android_version,
		"version": pc_version,
		"android_url": "https://github.com/shishkabob27/CardWarsKingdom/releases",
		"pc_url": "https://github.com/shishkabob27/CardWarsKingdom/releases",
	}
	return json.dumps(data)

class Player(db.Model):
	username = db.Column(db.String(80), primary_key=True, unique=True, nullable=False)
	game = db.Column(db.String(8192), nullable=True)
	multiplayer_name = db.Column(db.String(128), nullable=True)
	icon = db.Column(db.String(128), nullable=True)
	deck = db.Column(db.String(1024), nullable=True)
	deck_rank = db.Column(db.String(16), nullable=True)
	landscapes = db.Column(db.String(1024), nullable=True)
	helper_creature = db.Column(db.String(1024), nullable=True)
	leader = db.Column(db.String(128), nullable=True)
	leader_level = db.Column(db.Integer, nullable=True)
	allyboxspace = db.Column(db.Integer, nullable=True)
	level = db.Column(db.Integer, nullable=True)
	friends = db.Column(db.String(8192), nullable=True, default="[]")
	friend_requests = db.Column(db.String(8192), nullable=True, default="[]")
	last_online = db.Column(db.Integer, nullable=True, default=int(time.time()))
	helpcount = db.Column(db.Integer, nullable=True, default=0)
	anonymoushelpcount = db.Column(db.Integer, nullable=True, default=0)
 
	def as_dict(self):
		return {c.name: getattr(self, c.name) for c in self.__table__.columns}

@app.route("/")
def Index():
	return "200 App server running"

@app.route("/persist/static/manifest.json")
def Manifest():
	with open("data/persist/manifest.json", "r") as f:
		return f.read()

#only works in v1.18.0
@app.route("/persist/static/blueprints", methods=['GET'])
def Blueprints():
	data = []
	for root, dirs, files in os.walk("data/persist/blueprints"):
		for file in files:
			data.append({
				"name": file.replace(".json", ""),
				"data": open(f"{root}/{file}", "r").read()
			})
	return jsonify(data)

#only works in v1.0.16 - v1.0.17
@app.route("/persist/static/Blueprints/<string:file>", methods=['GET'])
def BlueprintsLegacy(file:str):
	if not file.startswith("db_") and not file.endswith(".json"):
		return make_response("Blueprint not found!", 404)
	if not os.path.exists(f"data/persist/blueprints/{file}"):
		return make_response("Blueprint not found!", 404)
	return open(f"data/persist/blueprints/{file}", "r").read()

@app.route("/account/preAuth/")
def AccountPreAuth():
	data = {
		"data": {
			"nonce": os.urandom(32).hex()
		}
	}
	return jsonify(data)

@app.route("/account/gcAuth/", methods=['POST'])
def AccountGCAuth():
	clientData = parse_qs(request.get_data().decode('utf-8'))
	clientData = {k: v[0] if len(v) == 1 else v for k, v in clientData.items()}
 
	#Create user if it doesn't exist
	db_user = Player.query.filter_by(username=clientData["player_id"]).first()
 
	isplayernew = False
 
	if db_user is None:
		db_user = Player(username=clientData["player_id"])
		db.session.add(db_user)
		db.session.commit()
		isplayernew = True     

	data = {
		"data": {
			"user_id": clientData["player_id"],
			"is_new": isplayernew
		}
	}
	return data

@app.route("/persist/getcc/")
def GetCountryCode():
	data = {
		"ip": "127.0.0.1",
		"country_code": "US"
	}
	return jsonify(data)

@app.route("/multiplayer/new_player/", methods=['POST'])
def MultiplayerNewPlayer():
	clientData = parse_qs(request.get_data().decode('utf-8'))
	clientData = {k: v[0] if len(v) == 1 else v for k, v in clientData.items()}

	db_user = Player.query.filter_by(username=clientData["player_id"]).first()
	if db_user is None:
		return make_response("No player found!", 404)

	db_user.multiplayer_name = clientData["name"]
	db_user.icon = clientData["icon"]
	db_user.deck_rank = clientData["deck_rank"]
	db_user.landscapes = clientData["landscapes"]
	db_user.helper_creature = clientData["helper_creature"]
	db_user.leader = clientData["leader"]
	db_user.leader_level = clientData["leader_level"]
	db_user.allyboxspace = clientData["allyboxspace"]
	db_user.level = clientData["level"]
	db.session.commit()
 
	return jsonify({
		"success": True,
		"data": {
			"name": clientData["name"],
			"icon": clientData["icon"],
			"leader": clientData["leader"],
			"level": str(clientData["leader_level"]),
			"trophies": "0" #TODO
		}
	})	

@app.route("/multiplayer/update_deck_name/", methods=['POST'])
def MultiplayerUpdateDeckName():
	clientData = parse_qs(request.get_data().decode('utf-8'))
	clientData = {k: v[0] if len(v) == 1 else v for k, v in clientData.items()}

	db_user = Player.query.filter_by(username=clientData["player_id"]).first()
	if db_user is None:
		return make_response("No player found!", 404)

	db_user.deck_rank = clientData["deck_rank"]
	db_user.landscapes = clientData["landscapes"]
	db_user.helper_creature = clientData["helper_creature"]
	db_user.leader = clientData["leader"]
	db_user.leader_level = clientData["leader_level"]
	db_user.allyboxspace = clientData["allyboxspace"]
 
	db.session.commit()
  
	return jsonify({
		"success": True
	})

@app.route("/persist/user_action2/", methods=['POST'])
def UserAction2():
	clientData = parse_qs(request.get_data().decode('utf-8'))
	clientData = {k: v[0] if len(v) == 1 else v for k, v in clientData.items()}
	
	UpdateLastOnline(clientData["player_id"])
 
	#Check if an event was sent
	if "evt" in clientData:
		db_user = Player.query.filter_by(username=clientData["player_id"]).first()
		if db_user is None:
			return make_response("No player found!", 404)
		
		FreeHardCurrency = int(clientData["fr"])
		df = int(clientData["df"])
  
		finalamount = FreeHardCurrency + df
  
		data = {
			"success": True,
			"data": "{\"fields\": {\"level2\": " + str(finalamount) + "}}"
		}
	else:
		data = {
			"success": True,
		}
	
	return jsonify(data) 

@app.route("/persist/<username>/game", methods=['GET', 'PUT'])
def PersistGame(username):
	UpdateLastOnline(username)
	
	if request.method == 'GET':
		db_user = Player.query.filter_by(username=username).first()
		if db_user is None:
			return make_response("No game found!", 404)
		if db_user.game is None:
			return make_response("No game found!", 404)
		if db_user.game == b"" or db_user.game == b" ":
			return make_response("No game found!", 404)
		return db_user.game

	if request.method == 'PUT':
		data = request.data
		db_user = Player.query.filter_by(username=username).first()
		if db_user is None:
			return make_response("No game found!", 404)
		db_user.game = data
		db.session.commit()
		return make_response("OK", 200)


def UpdateLastOnline(player_id):
	user = Player.query.filter_by(username=player_id).first()
	if user is None:
		return None
	user.last_online = int(time.time())
	db.session.commit()

def AllyBoxSpaceNotExceeded(player_id):
	user = Player.query.filter_by(username=player_id).first()
	if user is None:
		return None

	#count number of friends
	friends = json.loads(user.friends)
 
	friends_count = 0
 
	for friend in friends:
		friend_user = Player.query.filter_by(username=friend).first()
		if friend_user is None:
			continue

		friends_count += 1
	
	return friends_count < user.allyboxspace

@app.route("/persist/friends/<string:player_id>")
def PersistFriends(player_id):
	UpdateLastOnline(player_id)
	db_user = Player.query.filter_by(username=player_id).first()
 
	if db_user is None:
		return make_response("No player found!", 404)

	data = []
 
	player_friends = json.loads(db_user.friends)
 
	for friend in player_friends:
		allyinfo = GetAllyInfo(friend, True)
		if allyinfo is not None:
			data.append(allyinfo)
 
	return jsonify(data)

@app.route("/persist/friends_find_candidatesDW/", methods=['POST'])
def PersistFriendsFindCandidates():
	clientData = parse_qs(request.get_data().decode('utf-8'))
	clientData = {k: v[0] if len(v) == 1 else v for k, v in clientData.items()}
 
	db_user = Player.query.filter_by(username=clientData["player_id"]).first()
 
	if db_user is None:
		return make_response("No player found!", 404)

	data = []
 
	player_friends = json.loads(db_user.friends)
 
	for friend in player_friends:
		allyinfo = GetAllyInfo(friend, True)
		if allyinfo is not None:
			data.append(allyinfo)
  
	data2 = {
		"success": True,
		"data": json.dumps(data)
	}
	return jsonify(data2)

@app.route("/persist/friends_use_friendDW/", methods=['POST'])
def PersistFriendsUseFriend():
	clientData = parse_qs(request.get_data().decode('utf-8'))
	clientData = {k: v[0] if len(v) == 1 else v for k, v in clientData.items()}
 
 
	db_ally = Player.query.filter_by(username=clientData["friendid"]).first()

	if db_ally is None:
		return make_response("No player found!", 500)

	db_ally.helpcount = int(db_ally.helpcount) + 1
	db.session.commit()
 
	data = {
		"success": True,
	}
	return jsonify(data)

@app.route("/persist/friends_request_withmyinfoDW/", methods=['POST'])
def PersistFriendsRequestWithMyInfo():
	clientData = parse_qs(request.get_data().decode('utf-8'))
	clientData = {k: v[0] if len(v) == 1 else v for k, v in clientData.items()}
 
	UpdateLastOnline(clientData["player_id"])
	
	try:
		invite_user = Player.query.filter_by(username=clientData["invite_id"].replace("_", "-")).first()
	except:
		return make_response("No player found!", 400)
	if invite_user is None:
		return make_response("No player found!", 400)

	db_user = Player.query.filter_by(username=clientData["player_id"]).first()
	if db_user is None:
		return make_response("No player found!", 400)


	inviteuserfr = json.loads(invite_user.friend_requests)

	#Player ally check
	allycheck = AllyBoxSpaceNotExceeded(clientData["player_id"])
	if allycheck == False:
		return jsonify({
			"success": True,
			"info": "exceed me"
		})
  
	#friend ally check
	friendallycheck = AllyBoxSpaceNotExceeded(clientData["invite_id"].replace("_", "-"))
	if friendallycheck == False:
		return jsonify({
			"success": True,
			"info": "exceed"
		})
 
	#check if player already sent a request
	if clientData["player_id"] not in invite_user.friend_requests:
		inviteuserfr.append(clientData["player_id"])
		invite_user.friend_requests = json.dumps(inviteuserfr)
		db.session.commit()
		return jsonify({
			"success": True
		})
	else:
		return jsonify({
			"success": True,
			"info": "duplicate"
		})
  
def GetAllyInfo(player_id: str, isally: bool):
	db_user = Player.query.filter_by(username=player_id).first()
	if db_user is None:
		return None
	if db_user.multiplayer_name is None:
		return None
	data = {
		"fields": {
			"user_id": db_user.username,
			"name": db_user.multiplayer_name,
			"icon": db_user.icon,
			"rankxp": db_user.leader_level,
			"helpcount": db_user.helpcount if db_user.helpcount is not None else "0",
			"anonymoushelpcount": db_user.anonymoushelpcount if db_user.anonymoushelpcount is not None else "0",
			"helpercreatureid": db_user.leader,
			"helpercreature": db_user.helper_creature,
			"landscapes": db_user.landscapes,
			"ally": "1" if isally else "0",
			"sincelastactivedate": str(int(time.time()) - db_user.last_online)	
		}
	}
	return data

@app.route("/persist/friends_all_requests_received/<string:player_id>", methods=['GET'])
def PersistFriendsAllRequestsReceived(player_id):
	db_user = Player.query.filter_by(username=player_id).first()
	if db_user is None:
		return make_response("No player found!", 400)

	data = []
 
	playerfriendrequests = json.loads(db_user.friend_requests)
 
	for friendrequest in playerfriendrequests:
		allyinfo = GetAllyInfo(friendrequest, False)
		if allyinfo is not None:
			data.append(allyinfo)
 
	return jsonify(data)

@app.route("/persist/friends_deny_request/<string:player_id>/<string:invite_id>", methods=['GET'])
def PersistFriendsDenyRequest(player_id, invite_id):
	db_user = Player.query.filter_by(username=player_id).first()
	if db_user is None:
		return make_response("No player found!", 400)

	UpdateLastOnline(player_id)	
 
	#remove friend request
	player_requests = json.loads(db_user.friend_requests)
	player_requests.remove(invite_id)
	db_user.friend_requests = json.dumps(player_requests)
 
	db.session.commit()
	return jsonify({
		"success": True
	})
 
@app.route("/persist/friends_confirm_request_withmyinfoDW/", methods=['POST'])
def PersistFriendsConfirmRequestWithMyInfo():
	clientData = parse_qs(request.get_data().decode('utf-8'))
	clientData = {k: v[0] if len(v) == 1 else v for k, v in clientData.items()}
 
	UpdateLastOnline(clientData["player_id"])
 
	db_user = Player.query.filter_by(username=clientData["player_id"]).first()
	if db_user is None:
		return make_response("No player found!", 400)

	#Player ally check
	allycheck = AllyBoxSpaceNotExceeded(clientData["player_id"])
	if allycheck == False:
		return jsonify({
			"success": True,
			"info": "exceed me"
		})
  
	#friend ally check
	friendallycheck = AllyBoxSpaceNotExceeded(clientData["invite_id"])
	if friendallycheck == False:
		return jsonify({
			"success": True,
			"info": "exceed"
		})

	#remove friend request
	player_requests = json.loads(db_user.friend_requests)
	player_requests.remove(clientData["invite_id"])
	db_user.friend_requests = json.dumps(player_requests)
 
	#add friend
	player_friends = json.loads(db_user.friends)
	player_friends.append(clientData["invite_id"])
	db_user.friends = json.dumps(player_friends)
 
	#add self to friend's friend list
	friend_user = Player.query.filter_by(username=clientData["invite_id"]).first()
 
	if friend_user is None:
		return make_response("No player found!", 400)

	friend_friends = json.loads(friend_user.friends)
	friend_friends.append(clientData["player_id"])
	friend_user.friends = json.dumps(friend_friends)
 
	db.session.commit()
 
	return jsonify({
		"success": True
	})
 
@app.route("/persist/friends_remove/<string:player_id>/<string:invite_id>", methods=['GET'])
def PersistFriendsRemove(player_id, invite_id):
	db_user = Player.query.filter_by(username=player_id).first()
	if db_user is None:
		return make_response("No player found!", 400)

	#remove friend
	player_friends = json.loads(db_user.friends)
	player_friends.remove(invite_id)
	db_user.friends = json.dumps(player_friends)
 
	#remove self from friend
	friend_user = Player.query.filter_by(username=invite_id).first()
 
	if friend_user is None:
		return make_response("No player found!", 400)

	friend_friends = json.loads(friend_user.friends)
	friend_friends.remove(player_id)
	friend_user.friends = json.dumps(friend_friends)
	
	db.session.commit()
 
	return jsonify({
		"success": True
	})


if __name__ == '__main__':
	app.run(debug=args.debug, port=args.port)

with app.app_context():
	db.create_all()