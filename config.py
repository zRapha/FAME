import os
import configparser


def load_config(c):
	"""
		Load configuration data.
	"""

	config = ''
	try:
		path = os.path.dirname(os.path.realpath(__file__))
		f = '/'.join([path, c])
		config = configparser.ConfigParser()
		config.read(f)
	except Exception as e:
		print("Error: {}".format(e))
	return config


file = load_config('config.ini')