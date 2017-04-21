from random import randint
import os

""""initialising players 1 & 2 to position 0"""
p1 = 0
p2 = 0

"""Generating the grid"""
row10 = range(91, 101)[::-1]
row9 = range(81, 91)
row8 = range(71, 81)[::-1]
row7 = range(61, 71)
row6 = range(51, 61)[::-1]
row5 = range(41, 51)
row4 = range(31, 41)[::-1]
row3 = range(21, 31)
row2 = range(11, 21)[::-1]
row1 = range(1, 11)

print "Online Snakes & Ladders Game!"

"""printing the grid"""
print row10, "\n", row9, '\n', row8, '\n', row7, '\n', row6, '\n', row5, '\n', row4, '\n', row3, '\n', row2, '\n', row1, '\n'

"""Method that checks if there is a snake or a ladder on the board and acts accordingly"""


def is_snake_or_is_ladder(n):
    ladders = {2: 38, 9: 31, 21: 42, 28: 84, 36: 44, 51: 67, 71: 91, 80: 100}
    snakes = {98: 78, 95: 75, 93: 73, 87: 24, 64: 60, 62: 19, 56: 53, 49: 11, 48: 26, 16: 6}

    if ladders.has_key(n):
        print "\nYou're on a Ladder, time to go up!"
        n = ladders[n]
    elif snakes.has_key(n):
        print "Oh no, you've landed on a snake, down you go!" \
              ""
        n = snakes[n]
    return n


def dice_roll(r):
    raw_input("Please press enter to roll the dice!")
    d = randint(1, 6)
    d += r
    return d


while p1 < 100 or p2 < 100:
    print "Its Player 1's Turn:\n"
    p1 = dice_roll(p1)
    print "\nCurrent status of Player 1:", p1, "and Player 2:", p2, '\n'
    p1 = is_snake_or_is_ladder(p1)

    if p1 > 99:
        print "Winner of the game is Player 1"
        break

    print "Its Player 2's Turn:\n"
    p2 = dice_roll(p2)
    p2 = is_snake_or_is_ladder(p2)
    print "\nCurrent status of Player 1:", p1, " and Player 2:", p2, '\n'

    if p2 > 99:
        print "Winner of the game is Player 2"
        break
