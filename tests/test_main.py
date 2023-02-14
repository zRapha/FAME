import unittest
import config as cfg


class TestMethods(unittest.TestCase):
	def test_armed_config(self):
		assert cfg.file.getint('armed', 'perturbations') > 0
		assert cfg.file.getint('armed', 'advFilesExpected') > 0
		assert cfg.file.getint('armed', 'rounds') >= cfg.file.getint('armed', 'advFilesExpected')
		assert cfg.file['armed']['model'] == "EMBER" or cfg.file['armed']['model'] == "SOREL"
		assert cfg.file.getboolean('armed', 'integrityCheck') is True or \
			   cfg.file.getboolean('armed', 'integrityCheck') is False

	def test_aimed_config(self):
		assert cfg.file.getint('aimed', 'perturbations') > 0
		assert cfg.file.getint('aimed', 'advFilesExpected') > 0
		assert cfg.file.getint('aimed', 'sizePopulation') >= 2
		assert cfg.file['aimed']['model'] == "EMBER" or cfg.file['aimed']['model'] == "SOREL"
		assert cfg.file.getboolean('aimed', 'integrityCheck') is True or \
			   cfg.file.getboolean('aimed', 'integrityCheck') is False

	def test_aimedrl_config(self):
		assert cfg.file.getint('aimedrl', 'perturbations') > 0
		assert cfg.file['aimedrl']['model'] == "EMBER" or cfg.file['aimedrl']['model'] == "SOREL"
		assert cfg.file.getboolean('aimedrl', 'train') is True or \
			   cfg.file.getboolean('aimedrl', 'train') is False
		assert cfg.file.getboolean('aimedrl', 'evaluate') is True or \
			   cfg.file.getboolean('aimedrl', 'evaluate') is False

	def test_gameup_config(self):
		assert cfg.file.getint('gameup', 'perturbations') > 0
		assert cfg.file['gameup']['model'] == "EMBER" or cfg.file['gameup']['model'] == "SOREL"
		assert cfg.file.getboolean('gameup', 'integrityCheck') is True or \
			   cfg.file.getboolean('gameup', 'integrityCheck') is False

	def test_defense_config(self):
		assert cfg.file.getint('defense', 'perturbations') > 0
		assert cfg.file['defense']['model'] == "EMBER" or cfg.file['defense']['model'] == "SOREL"

	def test_compare_config(self):
		assert cfg.file.getint('compare', 'perturbations') > 0
		assert cfg.file.getint('compare', 'advFilesExpected') > 0
		assert cfg.file.getint('compare', 'rounds') >= cfg.file.getint('compare', 'advFilesExpected')
		assert cfg.file['compare']['model'] == "EMBER" or cfg.file['compare']['model'] == "SOREL"


if __name__ == '__main__':
	unittest.main()
