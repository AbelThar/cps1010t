class Ship:
	def __init__(self, size):
		print"SHIP INIT TEST"
		self.parts = []
		for x in range(size):
			self.parts.append(True)
		
