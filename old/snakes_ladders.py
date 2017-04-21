from random import randint

player1 = 0
player2 = 0

a = range(1,11)
b = range(11,21)[::-1]
c = range(21,31)
d = range(31,41)[::-1]
e = range(41,51)
f = range(51,61)[::-1]
g = range(61,71)
h = range(71,81)[::-1]
i = range(81,91)
j = range(91,101)[::-1]
print "Snakes and Ladders Game",'\n'
print j,'\n',i,'\n',h,'\n',g,'\n',f,'\n',e,'\n',d,'\n',c,'\n',b,'\n',a,'\n'

n1 = raw_input("Player 1, enter your name:\t")
n2 = raw_input("Player 2, enter your name:\t")

def check_for_snakes_and_ladders(n):
	"""This method checks for the presence of snakes or ladders in the board"""
	ladders = {1:38,4:14,9:31,21:42,28:84,36:44,51:67,71:91,80:100}
	snakes = {98:78,95:75,93:73,87:24,64:60,62:19,56:53,49:11,48:26,16:6}
	if ladders.has_key(n):
		print "Its a ladder,Climb up"
		n = ladders[n]
	elif snakes.has_key(n):
		print "Its a snake!!,Come down"
		n = snakes[n]
	return n


def roll_dice(r):
	"""This method takes input from each of the players, prints the current position of the players and checks for the
	winner of the game"""
	w = int(raw_input("Wish for Dice: "))
	if w <= 1 or w >= 6:
		print "I wish to be a millionaire, but we both know that is not happening anytime soon."
	
	d = randint(1,6)
	print "Rolling...you rolled a", d, "."
	if(d == w):
		print "Lucky you, nice roll.\n"
	elif(abs(w-d) == 1):
		print "Oof...almost, but not quite.\n"
	else:
		print "Don't worry; you'll get it next time.\n"
	d = r + d
	return d

while player1 < 100 or player2 < 100:
	print "\nIt's", n1,"'s turn\n"
	player1 = roll_dice(player1)
	player1 = check_for_snakes_and_ladders(player1)
	print "Current Score:,", n1,":",player1,"and ",n2,":",player2

	if player1 > 99:
		print "Congratulations player1, You Won!"
		break

	print "\nIt's", n2,"'s turn\n"
	player2 = roll_dice(player2)
	player2 = check_for_snakes_and_ladders(player2)
	print "Current status of Player1:",player1," and Player2:",player2

	if player2 > 99:
		print "Winner of the game is player2"
		break