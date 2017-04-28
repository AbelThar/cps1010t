import os
import re
import random
import hashlib
import hmac
import battlefield
import bombfield
import ship
import sys
import player

from string import letters
from operator import is_not
from functools import partial
from random import randint
from time import sleep

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
							   autoescape = True)

secret = open("secret.txt",'r').read()

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

class WebHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		params['user'] = self.user
		return render_str(template, **params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))

def render_post(response, post):
	response.out.write('<b>' + post.subject + '</b><br>')
	response.out.write(post.content)

def make_salt(length = 5):
	return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
	return db.Key.from_path('users', group)

class User(db.Model):
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	online = db.BooleanProperty()
	email = db.StringProperty()

	def render(self):
		return render_str("friend.html", f = self)

	def game_render(self):
		return render_str("game-friend.html", f = self)

	@classmethod
	def by_id(cls, uid):
		return cls.get_by_id(uid, parent = users_key())

	@classmethod
	def by_name(cls, name):
		u = cls.all().filter('name =', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return User(parent = users_key(),
					name = name,
					pw_hash = pw_hash,
					email = email)

	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			u.online = True
			u.put()
			return u

	@classmethod
	def logout(cls, u):
		if u:
			u.online = False
			u.put()

class Friends(db.Model):
	from_user = db.ReferenceProperty(User, collection_name = "from_user")
	to_user = db.ReferenceProperty(User, collection_name = "to_user")
	status = db.BooleanProperty()

	def render(self):
		return render_str("friend.html", f = self)

	@classmethod
	def relation(cls, user):
		relation = {}
		for to in user.from_user:
			relation[to.to_user] = to.status
		for frm in user.to_user:
			relation[frm.from_user] = frm.status
		return relation
	
	@classmethod
	def friends(cls, user):
		relation = Friends.relation(user)
		friends = {k: v for k, v in relation.iteritems() if v is True}.keys()
		return friends

	@classmethod
	def pending(cls, user):
		relation = Friends.relation(user)
		pending = {k: v for k, v in relation.iteritems() if v is False}.keys()
		return pending

	@classmethod
	def online(cls, user):
		# related_users = Friends.relation(user).keys()
		# online = list(users for users in related_users if users.online is True)
		online = list(users for users in Friends.friends(user) if users.online is True)
		return sorted(online, key=lambda user: user.name)

	@classmethod
	def offline(cls, user):
		# related_users = Friends.relation(user).keys()
		# offline = list(users for users in related_users if users.online is False)
		offline = list(users for users in Friends.friends(user) if users.online is False)
		return sorted(offline, key=lambda user: user.name)

	@classmethod
	# Returns all Friends() Class Objects where the user given, is set as the to_user; i.e for whom the invitation is sent
	def recieved(cls, user):
		pending_users = Friends.pending(user)
		recieved = [recieve.from_user.filter("to_user =", user).get() for recieve in pending_users]
		return filter(partial(is_not, None), recieved) # Removes Null for when no object was retrieved

	@classmethod
	# Returns all Friends() Class Objects where the user given, is set as the from_user; i.e who sent the invitation
	def sent(cls, user):
		pending_users = Friends.pending(user)
		sent = [send.to_user.filter("from_user =", user).get() for send in pending_users]
		return filter(partial(is_not, None), sent) # Removes Null for when no object was retrieved
	
	@classmethod
	def delete(cls):
		cls.get.delete()

class MainFront(WebHandler):
	def get(self):
		self.render('front.html')

class FriendsPage(WebHandler):
	def get(self):
		if self.user:
			recieved = sorted([f.from_user for f in Friends.recieved(self.user)], key=lambda user: user.name)
			online = Friends.online(self.user)
			offline = Friends.offline(self.user)
			sent = sorted([f.to_user for f in Friends.sent(self.user)], key=lambda user: user.name)

			# print [rec.from_user.name for rec in recieved]
			# print [on.name for on in online]
			# print [off.name for off in offline]
			# print [snt.to_user.name for snt in sent]

			self.render("friends.html", online = online, offline = offline, recieved = recieved, sent = sent)
		else:
			self.redirect("/login")

class NewFriend(WebHandler):
	def get(self):
		if self.user:
			self.render("newfriend.html")
		else:
			self.redirect("/login")

	def post(self):
		if not self.user:
			self.redirect('/')

		target_input = self.request.get('target')

		if target_input:
			target_user = User.by_name(target_input)
			
			if target_user:

				if target_user.name != self.user.name:
						
						accepted = [user for user in Friends.friends(self.user) if user.name == target_user.name]
						recieved = [target for target in Friends.recieved(self.user) if target.to_user.name == self.user.name and target.from_user.name == target_user.name]
						sent = [target.to_user for target in Friends.sent(self.user) if target.to_user.name == target_user.name and target.from_user.name == self.user.name]

						# print [acc.name for acc in accepted]
						# print [rec.from_user.name for rec in recieved]
						# print [snt.name for snt in sent]
						# return

						if accepted:
							return self.render("newfriend.html", status="accepted", target=target_input)

						elif recieved:
							for friendships in recieved:
								friendships.status = True
								friendships.put()
							return self.render("newfriend.html", status="recieved", target=target_input)

						elif sent:
							return self.render("newfriend.html", status="past_sent", target=target_input)

						else:
							f = Friends(from_user = self.user, to_user = target_user, status = False)
							f.put()
							return self.render("newfriend.html", status="new_sent", target=target_input)

				else:
					error = "Cannot send an invite to be friends with yourself."
					self.render("newfriend.html", error=error)
			else:
				error = "User with the given username, does not exist."
				self.render("newfriend.html", target_input=target_input, error=error)
		else:
			error = "Enter the username, to send an invite to be friends."
			self.render("newfriend.html", target_input=target_input, error=error)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
	return not email or EMAIL_RE.match(email)

class Signup(WebHandler):
	def get(self):
		self.render("signup-form.html")

	def post(self):
		have_error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')

		params = dict(username = self.username,
					  email = self.email)

		if not valid_username(self.username):
			params['error_username'] = "That's not a valid username."
			have_error = True

		if not valid_password(self.password):
			params['error_password'] = "That wasn't a valid password."
			have_error = True
		elif self.password != self.verify:
			params['error_verify'] = "Your passwords didn't match."
			have_error = True

		if not valid_email(self.email):
			params['error_email'] = "That's not a valid email."
			have_error = True

		if have_error:
			self.render('signup-form.html', **params)
		else:
			self.done()

	def done(self, *a, **kw):
		raise NotImplementedError

class Register(Signup):
	def done(self):
		#make sure the user doesn't already exist
		u = User.by_name(self.username)
		if u:
			msg = 'That user already exists.'
			self.render('signup-form.html', error_username = msg)
		else:
			u = User.register(self.username, self.password, self.email)
			u.online = True
			u.put()

			self.login(u)
			self.redirect('/')

class Login(WebHandler):
	def get(self):
		self.render('login-form.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		u = User.login(username, password)
		if u:
			self.login(u)
			self.redirect('/')
		else:
			msg = 'Invalid login'
			self.render('login-form.html', error = msg)

class Logout(WebHandler):
	def get(self):
		if self.user:
			User.logout(self.user)
		self.logout()
		self.redirect('/')

class UserStat(WebHandler):
	def get(self):
		if self.user:
			User.logout(self.user)
			
#######################BATTLESHIPS##############################
		
class Battleships(db.Model):
		player1 = db.ReferenceProperty(User, collection_name = "Battleships_p1")
		player2 = db.ReferenceProperty(User, collection_name = "Battleships_p2")

		cpu = db.BooleanProperty() #BOT FUNCTION no bot yet 
		p1_turn = db.BooleanProperty()
		state = db.IntegerProperty()
		
		rec_next = db.StringProperty()
		msg = db.StringProperty()

		nth = {
				1: "first",
				2: "second",
				3: "third",
				4: "fourth",
				5: "fifth"
			}

		rowlist = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"]	
			
	
	
class BattleshipsMenu(WebHandler):

	def get(self):
		if self.user:
			self.render('battleships-menu.html')
		else:
			self.redirect("/login")

	def post(self):
		if not self.user:
			self.redirect("/login")
		
		player = self.request.get('player')

		if player!="":
			user_p2 = User.by_name(player)

			if user_p2 is None:
				error = "Player Not Found" 
				self.render("battleships-menu.html", error = error)

			elif user_p2.name == self.user.name:
				error = "Cannot play on your own. Try playing with a bot."
				self.render("battleships-menu.html", error = error)

			else:
				opp = Battleships(player1 = self.user, player2 = user_p2, cpu = False, p1_turn = True, state = 0, waiter = True)
				opp.put()
				self.redirect('/battleshipsgame/%s' % str(opp.key().id()))

		else:
			opp = Battleships(player1 = self.user, cpu = True, p1_turn = True, state = 0)
			opp.put()
			self.redirect('/battleshipsgame/%s' % str(opp.key().id()))

class BattleshipsGame(WebHandler):
	#,heid=p1_h, leid=p1_l, heib=p2_h, leib=15+p2_l  Code for the coins 
	def height(cls, num):
		return 735-int((num-1)/10)*79.44444444

	def left(cls, num):
		ld = 79.44444444 * (9 if int(num%10)==0 else int(num%10)-1)
		ld = (715 - ld) if int((num-1)/10)%2 == 1 else ld
		return 5+ld
		
	
	def get(self, session_id):
	
		if self.user:
			sid = db.Key.from_path('Battleships', int(session_id))
			battleships = db.get(sid)

			if battleships:

				if battleships.state == 6:
					battleships.msg=""
				
				print "\n\nG:WUBBA LUBBA DUB DUB\n[",self.user.name,"]\n[1]:\t", battleships.msg,"\n[S]:\t", battleships.state,"\n\n"
				print battleships.state
				print "MRPPYBTTHLE"

				player2 = "Bot Bit" if battleships.cpu else battleships.player2.name

				if self.user.name == battleships.player1.name or (not battleships.cpu and self.user.name == player2):
					
					waiting = not battleships.cpu and (self.user.name == battleships.player1.name and not battleships.p1_turn) or (self.user.name == player2 and battleships.p1_turn) #and battleships.state == 0
					print "\n\nG1:WUBBA LUBBA DUB DUB\n[",self.user.name,"]\n[1]:\t", battleships.msg,"\n[wait]:\t", waiting,"\n[S]:\t", battleships.state,"\n\n"
					
					print "Ren"
					self.render("battleships-game.html", wait=waiting, state=battleships.state, msg=battleships.msg, player1=battleships.player1.name, player2="Bot Bit" if battleships.cpu else battleships.player2.name)
					print "Ren"

					if battleships.state > 1 or waiting: #and battleships.state < 10:
						sleep(2)

				else:
					self.redirect("/login")
				
			else:
				self.redirect("/battleships")

		else:
			self.redirect("/login")
	
	######################################################################################
	

	def post(self, session_id ):
	
			def clear(self):
				os.system('tput reset') #clears the terminal window, does not just add new lines but deletes whats been written
				
			def Start(self,db,):	
				### CREATE PLAYER VARIABLES ###
				print"CREATE"
				self.p1 = ""
				self.p2 = ""
				
				### CREATE BATTLEFIELDS ###
				self.p1Field = battlefield.Battlefield()
				self.p2Field = battlefield.Battlefield()
				self.p1BombField = bombfield.Bombfield()
				self.p2BombField = bombfield.Bombfield()
				

				### CREATE SHIPS ###
			
				self.ships = [];
				 #REMOVE APPENDS TO ADD SHIPS
				'''=self.ships.append(ship.Ship(5))
				self.ships.append(ship.Ship(4))
				self.ships.append(ship.Ship(3))
				self.ships.append(ship.Ship(3))'''
				self.ships.append(ship.Ship(2))
				
				#print"TESTING SHIPS 1" , ship.Ship(2) ,"\n\n"
				db.state = 1 
				db.put()
				
				
			def columnExist(self, column):
				if("A" <= column <= "J"): #is the column A-J?
					return True
				else:
					return False

			def rowExist(self, row):
				if(1 <= row <= 10): #is the row 1-10?
					return True
				else:
					return False
	    
			def printfield(self, f):
				
				l = [' ', 'A','B','C','D','E','F','G','H','I','J'] #Creates the header
				spacing = ' '.join(['{:<2}'] * len(l)) #creates a string with len(l)-numbers of '{:<2}' with a space between each one
				text = spacing.format(*l) #prints the header (column names) with a spacing of 2

				for v in range(1,len(l)):
					text += "\n" + spacing.format(v, f['A'][v],f['B'][v],f['C'][v],f['D'][v] ,f['E'][v] ,f['F'][v] ,f['G'][v] ,f['H'][v] ,f['I'][v],f['J'][v]) #Adds all the rows with the row number to the left and a spacing of 2

				return text
			
			def placeShips(self  , FieldShips):
				counter = 1
				#x = 0 
				### PLAYER INSTRUCTIONS ###
				db.msg = "" 
				
				print"PlaceShips FIRST TEST" , player, "\n\n"				
				#db.msg = " You have 10x10 cells where you can place your ships ,say which direction the ship is turned (right, left, up or down)"
				#print player.name + ", you have 10x10 cells where you can place your ships,\n"
				#print "Remember not to tell your opponent where you place your ships\n"
				#print "Then you say which direction the ship is turned (right, left, up or down)\n"

				#print(self.printfield(player.field.field)) #prints the player's field 

				### PLACE SHIPS ###
				#if x < 5 :
				for x in player.ships:
					#x = x + 1 
					print"placeships SECOND TEST"
					db.msg = ' You have 10x10 cells where you can place your ships ,say which direction the ship is turned (right, left, up or down)'
					column = ""
					row = ""
					direction = ""
					cellBusy = True
					pff = player.field.field
					while self.columnExist(column) == False or row not in rowlist or cellBusy == True: #loop until the user enters a valid cell
						userInput = raw_input(player.name + ", in which cell (A-J)(1-10) do you want to place your " + nth[counter] + " ship?\n") #user input for cell
						if (len(userInput) >= 2): #user input must be atleast 2 characters
							column = userInput[0].upper() #make userinput upper-case
							row = userInput[1]
							if len(userInput) >= 3: #since there is 10 rows, grab the third entered character too (if any)
								row += userInput[2]
						if(self.columnExist(column) and row in rowlist): #If the column and row is valid, check if the cell is busy
							cellBusy = pff[column][int(row)]
					
					row = int(row) #row is converted to integer here because now the entered row must be a valid integer

					newrow = row
					newcolumn = column
					
					while (direction != "right" and direction != "left" and direction != "up" and direction != "down") or self.rowExist(newrow) == False or self.columnExist(newcolumn) == False or cellBusy == True: #loop until the user enters a valid direction
						direction = raw_input(player.name + ", in what direction (right, left, up or down) is your " + nth[counter] + " ship turned?\n") #user input for direction
						cellBusy = False    
						partCounter = 0

						for y in range(len(x.parts)): #For each part of the current ship check if the cell is available
							newcolumn = column
							newrow = row
							if(direction == "down"):
								newrow = row + partCounter
								
							elif (direction == "up"):
								newrow = row - partCounter
								
							elif (direction == "left"):
								newcolumn = chr(ord(column) - partCounter) #chr(ord(a) - b) convert 'a' to ASCII, subtract b and convert back the result to a character
								
							elif(direction == "right"):
								newcolumn = chr(ord(column) + partCounter)
								
							partCounter += 1
							if self.columnExist(newcolumn) and self.rowExist(newrow):
								if pff[newcolumn][newrow] == True: #is the cell busy?
									cellBusy = pff[newcolumn][newrow]
								
								elif pff[newcolumn][newrow] == False and partCounter == len(x.parts): #if the last cell is available fill all the checked cells
									for p in range(0, partCounter):
										if(ord(newcolumn) < ord(column)):
											pff[chr(ord(column)-p)][newrow] = True
										elif(ord(newcolumn) > ord(column)):
											pff[chr(ord(column)+p)][newrow] = True
										elif(newrow < row):
											pff[newcolumn][newrow + p] = True
										elif(newrow > row):
											pff[newcolumn][newrow - p] = True
											
					#print(self.printfield(player.field.field))
					counter += 1
					db.state = 2
					db.put()

			def newPlayer(self, n, ships, field, bombfield): #Creates a new player with the given ships, field and bombfield
				newName = raw_input("Player " + str(n) + ", what's your name?\n")
				while newName == "":
					newName = raw_input("Please, enter something\n")
				self.clear()
				p = player.Player(newName, ships[:], field, bombfield)

				self.placeShips(p)
				return p #Returns the player object

			def anythingLeft(self, d): #Checks if there is any ships left on the given field
				newList = []
				def myprint(d):
					for k, v in d.iteritems():
						if isinstance(v, dict): #If v is a dict, call the function with that dict
						  myprint(v)
						else:
						  newList.append(v) #Else, add v (False/True) to the dict
				myprint(d)
				return True in newList #Returns True if there is a True in the list, else return False

			def selectCell(self, player): #Lets the player select a cell to bomb
				column = ""
				row = ""
				while self.columnExist(column) == False or row not in rowlist: #loop until given a valid cell
					userInput = raw_input(player.name + ", in which cell (A-J)(1-10) do you want to bomb your enemy?\n")

					if (len(userInput) < 2): #Reset both values if the input is less than 2 characters
						column = ""
						row = ""
					else: #Set row and column
						column = userInput[0].upper() #Convert input to upper-case
						row = userInput[1]
						if len(userInput) == 3: #since there is 10 rows, grab the third entered character too (if any)
							row += userInput[2]

				return [column, row]

			def bomb(self, player, enemy, column, row): #Gives the given player a chance to bomb the given enemy
				eff = enemy.field.field 
				self.result = '' #self.result, saves the latest result from a bombing

				row = int(row)
				if(eff[column][row] == True): #if there is a ship at the cell, set an x in the bombfield
					self.result = 'X' 
					eff[column][row] = 'X' #mark the enemy's ship field as hit 
					player.bombfield.field[column][row] = 'X' #mark the current players bombfiled as hit

					if self.anythingLeft(eff) == False: #Does the enemy have any ships left?
						self.result = player.name + " wins!"
				else:
					self.result = 'O'
					eff[column][row] = '@' #mark the enemy's ship field as missed
					if player.bombfield.field[column][row] != 'X': #only mark as missed if you have not hit a ship there before
						player.bombfield.field[column][row] = 'O'

			sid = db.Key.from_path('Battleships', int(session_id))
			battleships = db.get(sid)
			
			if battleships.state == 0: #Begins The Process When the submit button is entered .
				if self.request.get('next'):
					battleships.rec_next = int(self.request.get('next'))
					battleships.put()
				else:
					self.redirect('/battleshipsgame/%s' % str(battleships.key().id()))


			player2 = "Bot Bit" if battleships.cpu else battleships.player2.name
			waiting= not battleships.cpu and ((self.user.name == battleships.player1.name and not battleships.p1_turn) or (self.user.name == player2 and battleships.p1_turn))
			
			if self.user:
				
				if self.user.name == battleships.player1.name or (not battleships.cpu and self.user.name == battleships.player2.name):
					
						if battleships.state == 0:
							print "\n\nP1:WUBBA LUBBA DUB DUB\n[",self.user.name,"]\n[1]:\t", battleships.msg,"\n[wait]:\t", waiting,"\n[S]:\t", battleships.state,"\n\n"
							#placeShips(self , battleships )
							Start(self,battleships)
							self.redirect('/battleshipsgame/%s' % str(battleships.key().id()))
							
						elif battleships.state == 1:
							print "\n\nP1:WUBBA LUBBA DUB DUB\n[",self.user.name,"]\n[1]:\t", battleships.msg,"\n[wait]:\t", waiting,"\n[S]:\t", battleships.state,"\n\n"
							#print"TESTING SHIPS 2" , self.ships ,"\n\n"
							placeShips(self , battleships )
							self.redirect('/battleshipsgame/%s' % str(battleships.key().id()))
						
						#elif battleships.state == 1:
							#print "\n\nP1:WUBBA LUBBA DUB DUB\n[",self.user.name,"]\n[1]:\t", battleships.msg,"\n[wait]:\t", waiting,"\n[S]:\t", battleships.state,"\n\n"
							#Ship(self , size )
							#self.redirect('/battleshipsgame/%s' % str(battleships.key().id()))
				
				else:
					self.redirect("/login")

				print "\n\nPE:WUBBA LUBBA DUB DUB\n[",self.user.name,"]\n[1]:\t", battleships.msg,"\n[wait]:\t", waiting,"\n[S]:\t", battleships.state,"\n\n"				
			
			else:
				self.redirect("/login")
				
				
			
			
#############SNAKES######################
class Snakes(db.Model):
	player1 = db.ReferenceProperty(User, collection_name = "snakes_p1")
	player2 = db.ReferenceProperty(User, collection_name = "snakes_p2")
	score1 = db.IntegerProperty()
	score2 = db.IntegerProperty()
	
	cpu = db.BooleanProperty()
	p1_turn = db.BooleanProperty()
	state = db.IntegerProperty()
	
	msg = db.StringProperty()
	rec_wish = db.IntegerProperty()

class SnakesMenu(WebHandler):

	def get(self):
		if self.user:
			self.render('game-menu.html', game = "Snakes and Ladders", online = Friends.online(self.user), offline = Friends.offline(self.user))
		else:
			self.redirect("/login")

	def post(self):
		if not self.user:
			self.redirect("/login")
		
		player = self.request.get('player')

		if player!="":
			user_p2 = User.by_name(player)

			if user_p2 is None:
				error = "Player Not Found"
				self.render("game-menu.html", error = error, game = "Snakes and Ladders", online = Friends.online(self.user), offline = Friends.offline(self.user))

			elif user_p2.name == self.user.name:
				error = "Cannot play on your own. Try playing with a bot."
				self.render("game-menu.html", error = error, game = "Snakes and Ladders", online = Friends.online(self.user), offline = Friends.offline(self.user))

			else:
				opp = Snakes(player1 = self.user, score1=1, score2=1, player2 = user_p2, cpu = False, p1_turn = True, state = 0, waiter = True)
				opp.put()
				self.redirect('/snakesgame/%s' % str(opp.key().id()))

		else:
			opp = Snakes(player1 = self.user, score1=1, score2=1, cpu = True, p1_turn = True, state = 0)
			opp.put()
			self.redirect('/snakesgame/%s' % str(opp.key().id()))

class SnakesGame(WebHandler):
	
	def height(cls, num):
		return 735-int((num-1)/10)*79.44444444

	def left(cls, num):
		ld = 79.44444444 * (9 if int(num%10)==0 else int(num%10)-1)
		ld = (715 - ld) if int((num-1)/10)%2 == 1 else ld
		return 5+ld

	def get(self, session_id):
		if self.user:
			sid = db.Key.from_path('Snakes', int(session_id))
			snakes = db.get(sid)

			if snakes:

				if snakes.state == 6:
					snakes.msg=""
				
				# print "\n\nG:WUBBA LUBBA DUB DUB\n[",self.user.name,"]\n[1]:\t", snakes.score1,"\n[2]:\t", snakes.score2,"\n[msg]:\t", snakes.msg,"\n[S]:\t", snakes.state,"\n\n"
				# print snakes.state
				# print "MRPPYBTTHLE"

				snakes.score1 = 100 if snakes.score1>100 else snakes.score1
				snakes.score2 = 100 if snakes.score2>100 else snakes.score2
				snakes.put()

				p1_h = self.height(snakes.score1)
				p1_l = self.left(snakes.score1)

				p2_h = self.height(snakes.score2)
				p2_l = self.left(snakes.score2)

				player2 = "Bot Bit" if snakes.cpu else snakes.player2.name

				if self.user.name == snakes.player1.name or (not snakes.cpu and self.user.name == player2):
					
					waiting = not snakes.cpu and (self.user.name == snakes.player1.name and not snakes.p1_turn) or (self.user.name == player2 and snakes.p1_turn) #and snakes.state == 0
					# print "\n\nG1:WUBBA LUBBA DUB DUB\n[",self.user.name,"]\n[1]:\t", snakes.score1,"\n[2]:\t", snakes.score2,"\n[msg]:\t", snakes.msg,"\n[wait]:\t", waiting,"\n[S]:\t", snakes.state,"\n\n"
					
					# print "Ren"
					self.render("snakes-game.html", wait=waiting, state=snakes.state, msg=snakes.msg, player1=snakes.player1.name, player2="Bot Bit" if snakes.cpu else snakes.player2.name, score1=snakes.score1, score2=snakes.score2, heid=p1_h, leid=p1_l, heib=p2_h, leib=15+p2_l)
					# print "Ren"

					if snakes.state > 1 or waiting: #and snakes.state < 10:
						sleep(2)

				else:
					self.redirect("/login")
				
			else:
				self.redirect("/snakes")

		else:
			self.redirect("/login")

	#############################################################################

	def post(self, session_id):

		def wish_dice(self, db):
			
			if db.rec_wish > 6 and db.rec_wish!=None:
				db.msg = "Yeah, don't get your hopes up about that one. Rolling</td><td><marquee>...</marquee>"
			elif db.rec_wish < 1 and db.rec_wish!=None:
				db.msg = "Cheer up, I'm sure you'll do better than that. Rolling</td><td><marquee>...</marquee>"
			else:
				db.msg = "One way to find out. Rolling</td><td><marquee>...</marquee>"

			db.state = 1
			db.put()

		
		def roll_dice(self, db, num):

			d = randint(1,6)

			# print "\n\nR1:WUBBA LUBBA DUB DUB\n[1]:\t", db.score1,"\n[2]:\t", db.score2,"\n[S]:\t", db.state,"\n\n"

			if self.user.name == db.player1.name:
				db.score1 += d
				num = db.score1
			elif self.user.name == db.player2.name:
				db.score2 += d
				num = db.score2

			# print "\n\nYO SHANDA\t\n\n"# % snakes.rec_wish if not snakes.rec_wish is None
			# print type(snakes.rec_wish)
			# print "\n\n"

			# print "\n\nR2:WUBBA LUBBA DUB DUB\n[1]:\t", db.score1,"\n[2]:\t", db.score2,"\n[S]:\t", db.state,"\n\n"

			db.msg = "...You rolled a " + str(d) + ". "
			if db.rec_wish:
				if(d == num):
					db.msg = db.msg + "Lucky you, nice roll."
				elif(abs(num-d) == 1):
					db.msg = db.msg + "Oof...almost, but not quite."
				else:
					db.msg = db.msg + "Don't worry; you'll get it next time."

			db.state = 2
			db.put()


		def check_for_snakes_and_ladders(self, db):

			ladders = {1:38,4:14,9:31,21:42,28:84,51:67,71:91,80:100}
			snakes = {98:79,95:75,93:73,87:24,64:60,62:19,17:7}
			db.msg = ""

			# print "\n\nS1:WUBBA LUBBA DUB DUB\n[1]:\t", db.score1,"\n[2]:\t", db.score2,"\n[S]:\t", db.state,"\n\n"
				
			if self.user.name == db.player1.name:

				if ladders.has_key(db.score1):
					db.score1 = ladders[db.score1]
					db.msg = "Its a ladder, Climb up :)"

				elif snakes.has_key(db.score1):
					db.score1 = snakes[db.score1]
					db.msg = "Its a snake!!, Come down :("

				db.msg += ' %d more to go. Keep it up!' % int(100-db.score1)

			elif self.user.name == db.player2.name:
				if ladders.has_key(db.score2):
					db.score2 = ladders[db.score2]
					db.msg = "Its a ladder, Climb up :)"

				elif snakes.has_key(db.score2):
					db.score2 = snakes[db.score2]
					db.msg = "Its a snake!!, Come down :("

				db.msg += ' %d more to go. Keep it up!' % int(100-db.score2)

			# print "\n\nS2:WUBBA LUBBA DUB DUB\n[1]:\t", db.score1,"\n[2]:\t", db.score2,"\n[S]:\t", db.state,"\n\n"
			db.state = 3
			db.put()


		def cpu(self, db):

			d = randint(1,6)
			db.score2 += d
			db.score2 = 100 if db.score2 > 100 else db.score2 

			ladders = {1:38,4:14,9:31,21:42,28:84,51:67,71:91,80:100}
			snakes = {98:79,95:75,93:73,87:24,64:60,62:19,17:7}

			db.msg = 'Bot Bit rolled a %d, totalling to %d.' % (d, db.score2)

			if ladders.has_key(db.score2):
				db.score2 = ladders[db.score2]
				db.msg += '  Looks like someone is moving up to %d.' % db.score2
			elif snakes.has_key(db.score2):
				db.score2 = snakes[db.score2]
				db.msg += '  Moving down to %d does not seem to have been planned.' % db.score2

			db.msg += '  Bot Bit has %d left to win.' % int(100-db.score2)
			db.put()

			# print "\n\nC:WUBBA LUBBA DUB DUB\n[1]:\t", db.score1,"\n[2]:\t", db.score2,"\n[S]:\t", db.state,"\n\n"


		sid = db.Key.from_path('Snakes', int(session_id))
		snakes = db.get(sid)

		def win_output(self, db):

			if db.score1>=db.score2:
				
				db.msg = "%s has won the game! " % db.player1.name

				if self.user.name == db.player1.name:
					db.msg += "Well Played!"

				elif not db.cpu:
					if self.user.name == db.player2.name:
						db.msg += "Better luck next time."

			else:
				if not db.cpu:
					db.msg = "%s has won the game! " % db.player2.name

					if self.user.name == db.player2.name:
						db.msg += "Well Played!"

					if self.user.name == db.player1.name:
						db.msg += "Better luck next time."

				else:
					db.msg = "Bot Bit has won the game! Better luck next time."

			db.put()

		# waiting = not snakes.cpu and (self.user.name == snakes.player1.name and not snakes.p1_turn) or (self.user.name == snakes.player2.name and snakes.p1_turn)
		# if waiting:
		# 	print "TOO OLD"
		# 	self.redirect('/snakesgame/%s' % str(snakes.key().id()))
		# 	return
		
		if snakes.state == 0:
			if self.request.get('wish'):
				snakes.rec_wish = int(self.request.get('wish'))
				snakes.put()
			else:
				self.redirect('/snakesgame/%s' % str(snakes.key().id()))

			
		p1_h = self.height(snakes.score1)
		p1_l = self.left(snakes.score1)

		p2_h = self.height(snakes.score2)
		p2_l = self.left(snakes.score2)

		player2 = "Bot Bit" if snakes.cpu else snakes.player2.name
		waiting= not snakes.cpu and ((self.user.name == snakes.player1.name and not snakes.p1_turn) or (self.user.name == player2 and snakes.p1_turn))

		#print snakes.state

		if self.user:

			if self.user.name == snakes.player1.name or (not snakes.cpu and self.user.name == snakes.player2.name):
				
				# print "\n\nCHecker"
				# print (snakes.state == 4 or snakes.state == 5)
				# print snakes.state

				if (snakes.score1>=100 or snakes.score2>=100) and (snakes.state < 5 or snakes.state == 50):
					# print "\nHERE 2\n"
					if snakes.state == 50:
						snakes.state = 6
						# print "\n\n", self.user.name, " will give the final turn"
						snakes.p1_turn = not snakes.p1_turn
					else:
						snakes.state = 5
					win_output(self, snakes)
					snakes.put()
					self.redirect('/snakesgame/%s' % str(snakes.key().id()))

				elif snakes.state == 0:
					# print "\n\nP1:WUBBA LUBBA DUB DUB\n[",self.user.name,"]\n[1]:\t", snakes.score1,"\n[2]:\t", snakes.score2,"\n[msg]:\t", snakes.msg,"\n[wait]:\t", waiting,"\n[S]:\t", snakes.state,"\n\n"
					wish_dice(self, snakes)
					self.redirect('/snakesgame/%s' % str(snakes.key().id()))

				elif snakes.state == 1:
					# print "\n\nP2:WUBBA LUBBA DUB DUB\n[",self.user.name,"]\n[1]:\t", snakes.score1,"\n[2]:\t", snakes.score2,"\n[msg]:\t", snakes.msg,"\n[wait]:\t", waiting,"\n[S]:\t", snakes.state,"\n\n"
					roll_dice(self, snakes, snakes.rec_wish)
					self.redirect('/snakesgame/%s' % str(snakes.key().id()))
				
				elif snakes.state == 2:
					# print "\n\nP3:WUBBA LUBBA DUB DUB\n[",self.user.name,"]\n[1]:\t", snakes.score1,"\n[2]:\t", snakes.score2,"\n[msg]:\t", snakes.msg,"\n[wait]:\t", waiting,"\n[S]:\t", snakes.state,"\n\n"
					check_for_snakes_and_ladders(self, snakes)
					self.redirect('/snakesgame/%s' % str(snakes.key().id()))

				elif snakes.state == 3:
					# print "\n\nP4:WUBBA LUBBA DUB DUB\n[",self.user.name,"]\n[1]:\t", snakes.score1,"\n[2]:\t", snakes.score2,"\n[msg]:\t", snakes.msg,"\n[wait]:\t", waiting,"\n[S]:\t", snakes.state,"\n\n"
					if snakes.cpu:
						cpu(self, snakes)
						if snakes.score2 >= 100:
							win_output(self, snakes)
							self.redirect('/snakesgame/%s' % str(snakes.key().id()))
					else:
						snakes.msg = "Waiting for opponent</td><td><marquee>...</marquee>"
					
					snakes.state = 4
					snakes.put()
					self.redirect('/snakesgame/%s' % str(snakes.key().id()))

				elif snakes.state == 4 or snakes.state == 5 or snakes.state == 6:
					# print "\nHERE 3\n"
					#snakes.state = 40 if snakes.state == 4 else 50
					if snakes.state == 6:
						win_output(self, snakes)

					# print "\nHERE 3:\t", snakes.msg,"\n\n"
					snakes.state *= 10
					snakes.rec_wish = None
					# if not snakes.cpu:
					# 	snakes.msg = "Waiting for opponent</td><td><marquee>...</marquee>"
					snakes.put()
					self.redirect('/snakesgame/%s' % str(snakes.key().id()))

				elif snakes.state == 40:
					if not snakes.cpu:
						snakes.p1_turn = not snakes.p1_turn
					snakes.state = 0
					snakes.put()
					self.redirect('/snakesgame/%s' % str(snakes.key().id()))

				elif snakes.state == 50:
					if snakes.cpu:
						snakes.delete()
						self.redirect("/snakes/")

				elif snakes.state == 60:
					snakes.state = 70
					snakes.put()
					self.redirect('/snakesgame/%s' % str(snakes.key().id()))

				elif snakes.state == 70:
					snakes.delete()
					self.redirect("/snakes/")

			else:
				self.redirect("/login")

				# print "\n\nPE:WUBBA LUBBA DUB DUB\n[",self.user.name,"]\n[1]:\t", snakes.score1,"\n[2]:\t", snakes.score2,"\n[msg]:\t", snakes.msg,"\n[wait]:\t", waiting,"\n[S]:\t", snakes.state,"\n\n"				
		
		else:
			self.redirect("/login")

app = webapp2.WSGIApplication([('/?', MainFront),
							   ('/friends', FriendsPage),
							   ('/newfriend', NewFriend),
							   ('/signup', Register),
							   ('/login', Login),
							   ('/logout', Logout),
							   ('/user', UserStat),
							   ('/battleships/?', BattleshipsMenu),
							   ('/battleshipsgame/([0-9]+)', BattleshipsGame),
							   ('/snakes/?', SnakesMenu),
							   ('/snakesgame/([0-9]+)', SnakesGame),
							   ],
							  debug=True)