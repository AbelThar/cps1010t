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
            self.render('snakes-menu.html')
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
                self.render("snakes-menu.html", error = error)

            elif user_p2.name == self.user.name:
                error = "Cannot play on your own. Try playing with a bot."
                self.render("snakes-menu.html", error = error)

            else:
                opp = Snakes(player1 = self.user, score1=1, score2=1, player2 = user_p2, cpu = False, p1_turn = True, state = 0)
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
            
            print "\n\nG:WUBBA LUBBA DUB DUB\n[1]:\t", snakes.score1,"\n[2]:\t", snakes.score2,"\n\n"

            p1_h = self.height(snakes.score1)
            p1_l = self.left(snakes.score1)

            p2_h = self.height(snakes.score2)
            p2_l = self.left(snakes.score2)

            if self.user.name == snakes.player1.name or (not snakes.cpu and self.user.name == player2):
                
                waiting = (self.user.name == snakes.player1.name and not snakes.p1_turn) or (not snakes.cpu and self.user.name == player2 and snakes.p1_turn)

                self.render("snakes-game.html", wait=waiting, state=snakes.state, msg=snakes.msg, player1=snakes.player1.name, player2="Bot Bit" if snakes.cpu else snakes.player2.name, score1=snakes.score1, score2=snakes.score2, heid=p1_h, leid=p1_l, heib=p2_h, leib=15+p2_l)

                while waiting:
                    sleep(0)
                    snakes = db.get(sid)
                    waiting = (self.user.name == snakes.player1.name and not snakes.p1_turn) or (not snakes.cpu and self.user.name == player2 and snakes.p1_turn)
                    if not waiting:
                        self.redirect('/snakesgame/%s' % str(snakes.key().id()))
            else:
                self.redirect("/login")

        else:
            self.redirect("/login")

    #############################################################################

    def post(self, session_id):

        def wish_dice(self, db):

            if db.rec_wish >= 6:
                db.msg = "Yeah, don't get your hopes up about that one. Rolling<marquee>...</marquee>"
            if db.rec_wish >= 1:
                db.msg = "Cheer up, I'm sure you'll do better than that. Rolling<marquee>...</marquee>"
            else:
                db.msg = "One way to find out. Rolling<marquee>...</marquee>"

            db.state = 1
            db.put()

        
        def roll_dice(self, db, num):

            d = randint(1,6)

            print "\n\nR1:WUBBA LUBBA DUB DUB\n[1]:\t", db.score1,"\n[2]:\t", db.score2,"\n\n"

            if self.user.name == db.player1.name:
                db.score1 += d
                num = db.score1
            elif self.user.name == db.player2.name:
                db.score2 += d
                num = db.score2

            print "\n\nR2:WUBBA LUBBA DUB DUB\n[1]:\t", db.score1,"\n[2]:\t", db.score2,"\n\n"

            msg = "...You rolled a " + str(d) + ". "
            if(d == num):
                db.msg = msg + "Lucky you, nice roll."
            elif(abs(num-d) == 1):
                db.msg = msg + "Oof...almost, but not quite."
            else:
                db.msg = msg + "Don't worry; you'll get it next time."

            db.state = 2
            db.put()


        def check_for_snakes_and_ladders(self, db):

            ladders = {1:38,4:14,9:31,21:42,28:84,51:67,71:91,80:100}
            snakes = {98:79,95:75,93:73,87:24,64:60,62:19,17:7}

            print "\n\nS1:WUBBA LUBBA DUB DUB\n[1]:\t", db.score1,"\n[2]:\t", db.score2,"\n\n"
                
            if self.user.name == db.player1.name:
                if ladders.has_key(db.score1):
                    db.score1 = ladders[db.score1]
                    db.msg = "Its a ladder, Climb up :)"

                elif snakes.has_key(db.score1):
                    db.score1 = snakes[db.score1]
                    db.msg = "Its a snake!!, Come down :("

            elif self.user.name == db.player2.name:
                if ladders.has_key(db.score2):
                    db.score2 = ladders[db.score2]
                    db.msg = "Its a ladder, Climb up :)"

                elif snakes.has_key(db.score2):
                    db.score2 = snakes[db.score2]
                    db.msg = "Its a snake!!, Come down :("

            print "\n\nS2:WUBBA LUBBA DUB DUB\n[1]:\t", db.score1,"\n[2]:\t", db.score2,"\n\n"
            db.state = 3
            db.put()


        def cpu(self, db):

            d = randint(1,6)
            db.score2 += d

            ladders = {1:38,4:14,9:31,21:42,28:84,51:67,71:91,80:100}
            snakes = {98:79,95:75,93:73,87:24,64:60,62:19,17:7}

            if ladders.has_key(db.score2):
                db.score2 = ladders[db.score2]
            elif snakes.has_key(db.score2):
                db.score2 = snakes[db.score2]

            db.put()

            print "\n\nC:WUBBA LUBBA DUB DUB\n[1]:\t", db.score1,"\n[2]:\t", db.score2,"\n\n"


        sid = db.Key.from_path('Snakes', int(session_id))
        snakes = db.get(sid)
        
        if snakes.state == 0:
            if isinstance(self.request.get('wish'), (int, long)):
                snakes.rec_wish = self.request.get('wish')
                snakes.put()
            
        p1_h = self.height(snakes.score1)
        p1_l = self.left(snakes.score1)

        p2_h = self.height(snakes.score2)
        p2_l = self.left(snakes.score2)

        player2 = "Bot Bit" if snakes.cpu else snakes.player2.name

        if self.user:
            if snakes.score1<100 and snakes.score2<100:

                if self.user.name == snakes.player1.name or (not snakes.cpu and self.user.name == snakes.player2.name):
                    
                    print "\n\nP1:WUBBA LUBBA DUB DUB\n[1]:\t", snakes.score1,"\n[2]:\t", snakes.score2,"\n\n"
                    if snakes.state == 0:
                        wish_dice(self, snakes)
                        self.redirect('/snakesgame/%s' % str(snakes.key().id()))

                    print "\n\nP2:WUBBA LUBBA DUB DUB\n[1]:\t", snakes.score1,"\n[2]:\t", snakes.score2,"\n\n"
                    elif snakes.state == 1:
                        roll_dice(self, snakes, snakes.rec_wish)
                        self.redirect('/snakesgame/%s' % str(snakes.key().id()))
                    
                    print "\n\nP3:WUBBA LUBBA DUB DUB\n[1]:\t", snakes.score1,"\n[2]:\t", snakes.score2,"\n\n"
                    elif snakes.state == 2:
                        check_for_snakes_and_ladders(self, snakes)
                        self.redirect('/snakesgame/%s' % str(snakes.key().id()))

                    print "\n\nP4:WUBBA LUBBA DUB DUB\n[1]:\t", snakes.score1,"\n[2]:\t", snakes.score2,"\n\n"
                    elif snakes.state == 3:
                        if snakes.cpu:
                            cpu(self, snakes)
                        else:
                            snakes.p1_turn = not snakes.p1_turn
                            
                        snakes.state = 0
                        snakes.put()
                        self.redirect('/snakesgame/%s' % str(snakes.key().id()))

                else:
                    self.redirect("/login")

                print "\n\nPE:WUBBA LUBBA DUB DUB\n[1]:\t", snakes.score1,"\n[2]:\t", snakes.score2,"\n\n"

            else:
                self.redirect("/snakes")
        
        else:
            self.redirect("/login")