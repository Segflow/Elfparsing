
class Addr(int):
	"""Used to represent adresses"""
	
	def __init__(self, arg):
		self.int = arg
	
	def __str__(self):
		return hex(self.int)

	def __add__(self,n):
		datatype = type(n)
		if datatype == Addr:
			return Addr(self.int + n.int)
		elif datatype == int:
			return Addr(self.int + n)
		else:
			raise TypeError("Only 'int' or 'Addr' can be added")