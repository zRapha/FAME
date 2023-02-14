#!/usr/bin/env python3
"""
Welcome to the Framework for Adversarial Malware Evaluation (FAME)

FAME was designed to understand how byte-level transformations could automatically be injected to Windows Portable
Executable (PE) files and compromise ML-based malware classifiers. Moreover, it supports integrity verification to
ensure that the new adversarial examples are valid. This work implements the action space proposed on the OpenAI gym
malware environment. It has been implemented in Fedora 30 and tested on Ubuntu 16 using Python3. Library versions are
defined in requirements.txt file.

The following modules are available: ARMED, AIMED, AIMED-RL & GAME-UP

GAME-UP: Generating Adversarial Malware Examples with Universal Perturbations

This work intends to understand how Universal Adversarial Perturbations (UAPs) can be useful to create efficient
adversarial examples compared to input-specific attacks. Furthermore, it explores how real malware examples in the
problem-space affect the feature-space of classifiers to identify systematic weaknesses. Also, it implements a variant
of adversarial training to improve the resilience of static ML-based malware classifiers for Windows PE binaries.

AIMED-RL: Automatic Intelligent Modifications to Evade Detection (with Reinforcement Learning)

This work is focused on understanding how sensitive static malware classifiers are to adversarial examples. It uses
different techniques including Genetic Programming (GP) and Reinforcement Learning (RL) to inject perturbations to
Windows portable executable malware without compromising its functionality and, thus, keeping the new generated
adversarial example valid.

"""

import sys
import time
import config as cfg
import functions as f
import implementation as i


def main(argv=sys.argv[1]):
	option = argv.upper()

	# Time algorithm
	start = time.time()

	# ARMED: Finding adversarial malware examples stochastically
	if option == 'ARMED':
		i.armed(number_perturbations=cfg.file.getint('armed', 'perturbations'),
				rounds=cfg.file.getint('armed', 'rounds'), files_expected=cfg.file.getint('armed', 'advFilesExpected'),
				model=cfg.file['armed']['model'])

	# ARMED II: Using Incremental Iterations of perturbations' sequence
	elif option == 'ARMED-II':
		i.armed2(number_perturbations=cfg.file.getint('armed', 'perturbations'),
				 rounds=cfg.file.getint('armed', 'rounds'),
				 files_expected=cfg.file.getint('armed', 'advFilesExpected'),
				 model=cfg.file['armed']['model'])

	# AIMED: Finding adversarial examples with genetic programming
	elif option == 'AIMED':
		i.aimed(size_population=cfg.file.getint('aimed', 'sizePopulation'),
				number_perturbations=cfg.file.getint('aimed', 'perturbations'),
				model=cfg.file['aimed']['model'])

	# AIMED-RL: Finding adversarial examples with reinforcement learning
	elif option == 'AIMED-RL':
		i.aimed_rl(base_path=cfg.file['paths']['rl'],
				   report_path=cfg.file['paths']['report'],
				   train=cfg.file.getboolean('aimedrl', 'train'),
				   evaluate=cfg.file.getboolean('aimedrl', 'evaluate'))

	# GAME-UP: Find universal perturbation sequences to generate adversarial examples
	elif option == 'GAMEUP':
		i.gameup(number_perturbations=cfg.file.getint('gameup', 'perturbations'), model=cfg.file['gameup']['model'],
				 exploration_set=cfg.file['paths']['exploration'],)

	# UAP-DEF: Use UAPs to increase resilience of models against universal attacks
	elif option == 'DEFENSE':
		i.defense(number_perturbations=cfg.file.getint('defense', 'perturbations'),
				  model=cfg.file['defense']['model'])

	# COMPARE: Evaluate different algorithms (Example imp.: AIMED vs ARMED)
	elif option == 'COMPARE':
		i.comparing(number_perturbations=cfg.file.getint('compare', 'perturbations'),
					rounds=cfg.file.getint('compare', 'rounds'),
					files_expected=cfg.file.getint('compare', 'advFilesExpected'),
					model=cfg.file['compare']['model'])

	else:
		exit('Option not found!')

	f.time_me(start)


if __name__ == '__main__':
	main()
