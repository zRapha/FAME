import os
import gp
import rl
import sys
import shutil
import random
import requests
import defense as d
import config as cfg
import functions as f
import data.manipulate as m
from datetime import datetime
from subprocess import call, check_output
from time import time, sleep, strftime, gmtime


# Create a dict with all perturbations
ACTIONS = f.actions_vector(m.ACTION_TABLE.keys())

# Paths
CSV_PATH = cfg.file['paths']['db']
NPZ_PATH = cfg.file['paths']['npz']
MOD_PATH = cfg.file['paths']['mod']
FAIL_PATH = cfg.file['paths']['fail']
EVASION_PATH = cfg.file['paths']['evasion']
DETECTED_PATH = cfg.file['paths']['detected']
MALWARE_PATH = cfg.file['paths']['malware_set']
EXPLORATION_SET = cfg.file['paths']['exploration']
VALIDATION_SET = cfg.file['paths']['validation']
MODEL_PATH = cfg.file['paths']['model_path']

# Default fields for database - Adjust to load list with Configparser
FIELDS = ['Original_File', 'OF_Detections', 'Manipulated_File', 'MF_Detections', 'Perturbations',
		  'Perturbations_Injected',
		  'Full_Detections_Report', 'Full_Analysis_Report', 'Mod_File_Hash', 'Original_File_Hash', 'Date_Reported']

# Use remote (VirusTotal) or local detection & remote (Hybrid Analysis) or local sandbox
useVT = cfg.file.getboolean('remote', 'useVT')
useHA = cfg.file.getboolean('remote', 'useHA')


# IMPLEMENTATION GAME-UP / AIMED / ARMED


def gameup(number_perturbations, model, exploration_set=EXPLORATION_SET):
	"""
		GAME-UP: Generating Adversarial Malware Examples with Universal Perturbations.
		This function searches for the best perturbation vector, which has
		the highest probability rate to generate adversarial examples in the
		problem-space given the byte-level transformations.

		Input:
			number_perturbations: number of perturbations to inject
			model: commercial AV or research malware classifier
	"""

	# Inject perturbations and check for detection
	current_round = 1
	chosen_actions = [None]
	size_perturbation_vector = 0
	number_actions = len(ACTIONS)
	number_files = len(os.listdir(exploration_set))
	total_rounds = number_perturbations * number_actions * number_files

	# Iterate each_pert times, which is the len of perturbation vector
	for each_perturbation in range(number_perturbations):

		# Applying each perturbation to every pool of malware files
		scores_average = {}
		for next_action in range(number_actions):

			# Picking sequentially each file from source folder
			scores = {}
			for sample in sorted(os.listdir(exploration_set)):

				# Skip file if it is labeled as problematic or not a file
				if 'error' in os.path.join(exploration_set, sample).lower() or not os.path.isfile(
						os.path.join(exploration_set, sample)):
					current_round += 1
					continue

				# Convert original malware sample into binaries
				bin_bytes = f.readfile(os.path.join(exploration_set, sample))

				# Chosen_actions will be the UAP
				chosen_actions[each_perturbation] = next_action
				size_perturbation_vector = len(chosen_actions)

				# Call recursive function to inject n perturbations on a sample
				print('\n### GAME-UP: Generating Adversarial Malware Examples with Universal Perturbations ###\n')
				print('## Manipulation Box # Round {} of {} # Perturbation {} of {} ##\n'.format(current_round,
																								 total_rounds,
																								 each_perturbation + 1,
																								 number_perturbations))
				print('Running analysis for:', sample)
				print('Injecting {} perturbation(s): {}'.format(size_perturbation_vector, chosen_actions))
				inject_perturbation = size_perturbation_vector - 1
				mod_sample = f.rec_mod_files(bin_bytes, ACTIONS, chosen_actions, inject_perturbation)

				# If modified file returns errors, label original & move to next
				if not mod_sample:
					os.rename(os.path.join(exploration_set, sample), exploration_set + 'LIEF_Error_' + sample)
					current_round += 1
					continue

				# Calculate hashes from original and modified sample
				hash_sample = f.hash_files(exploration_set + sample)
				mod_sample_hash = f.hash_files(mod_sample)

				# Check whether original malware is detected
				print('\n## Malware Classifier: Original File ##\n')
				original_sample_detected, _ = malware_detection(exploration_set + sample, model)
				sample_report = {'positives': 1, 'total': 1}  # legacy compatibility with VT

				# Collect info to writeCSV function
				CSV = f.collect_info_CSV(exploration_set + sample, sample_report, size_perturbation_vector,
										 chosen_actions, mod_sample_hash, hash_sample)

				# Malware analysis & malware detection stages
				print('## Sandbox (Oracle) # Round {} of {} ##'.format(current_round, total_rounds))

				# Only proceed if original malware is detected
				print('\nChecking functionality of adversarial example:\n')
				if original_sample_detected:
					if cfg.file.getboolean('gameup', 'integrityCheck'):
						funcional, url_sandbox = malware_analysis(mod_sample, useVT, CSV)
					else:
						# When f.batch_functionality_test() is used instead of online verification
						funcional, url_sandbox = True, "www.no_integrity_test.com"
				else:
					print('Original malware not detected by model. Skipping adversarial analysis.\n')
					current_round += 1
					continue

				# Check if modified sample is detected
				print('## Malware Classifier: Adv. Example # Round {} of {} ##\n'.format(current_round, total_rounds))
				print('Running detection for:', mod_sample)
				detected, mod_sample_score = malware_detection(mod_sample, model)

				# Save functional detected or adversarial examples in DB
				if funcional:
					mutation_name = str(size_perturbation_vector) + '_m.exe'
					save_file_database(detected, mutation_name, url_sandbox, CSV, model)

				scores[str(current_round)] = mod_sample_score
				current_round += 1
				# print('Scores:', scores)

			current_average = sum(scores.values()) / number_files
			scores_average[str(next_action)] = current_average
			print('\nScores (Avg):', scores_average)

		best_perturbation = min(scores_average, key=scores_average.get)
		chosen_actions[each_perturbation] = int(best_perturbation)
		chosen_actions.append(0)

	# Show results
	print('\n## Summary ##\n')
	print('\nPotential UAP: {}'.format(chosen_actions[:size_perturbation_vector]))

	return chosen_actions[:size_perturbation_vector]


def defense(number_perturbations, model):
	"""
		Use UAP vector found with GAME-UP module to approximate the noise and
		generate synthetic adversarial examples, which would be use to perform
		adversarial training (pure & mixed) and, thus, increase resilience of
		ML-based malware classifiers.

		Input:
			number_perturbations: number of perturbations to inject
			model: commercial AV or research malware classifier

	"""

	uap_def = d.Defense(model=model, csv_path=CSV_PATH, features_path=NPZ_PATH, number_examples=300000)  # 50000

	# GENERATE ATTACK

	# Find UAP vector
	print('\n1. Calculating UAP vector')
	uap_v = gameup(number_perturbations=number_perturbations, model=model, exploration_set=EXPLORATION_SET)

	# Create datasets
	print('\n2. Validating UAP vector & saving features of original & adversarial malware examples')
	uap_def.create_uap_datasets(csv_path=CSV_PATH, features_path=NPZ_PATH, uap_vector=uap_v)

	# Extract perturbations as variation between original and adversarial examples
	print('\n3. Extract noise from features of problem-space malware (original - adversarial)')
	noise_feature = uap_def.extract_perturbation_from_features(features_path=NPZ_PATH)

	# IMPROVE DEFENSES

	# Adversarial training Pure & Mixed
	print('\n4. Train baseline model (a) and perform adversarial training two-fold (b & c):\n')
	uap_def.adversarial_training(noise_feature)

	# Feature reduction
	print('\n5. Apply feature reduction and train model:')
	uap_def.train_feature_reduction(model_path=MODEL_PATH, features_path=NPZ_PATH)


def aimed(size_population, number_perturbations, model, check_exploration_set=False):
	"""
		AIMED: Automatic Intelligent Malware Modifications to Evade Detection
		This function implements GP to find PE adversarial examples.

		Input:
			size_population: population size for GP (Default: 4)
			number_perturbations: length of perturbation sequence
			files_expected: number of malware mutations expected as output
			model: commercial AV or malware model classifier
	"""

	print('\n### AIMED: Automatic Intelligent Malware Modifications to Evade Detection ###')

	search_UAP = cfg.file.getboolean('aimed', 'searchUAP')

	# Parse folder until find a malware sample that is detected to start
	print('\nSearch for detected file as input object..\n')
	sample = None
	original_sample_detected = False
	while not original_sample_detected:
		sample = os.path.join(MALWARE_PATH, random.choice(os.listdir(MALWARE_PATH)))
		# Skip file if it is labeled as problematic or not a file
		if 'error' in sample.lower() or not os.path.isfile(sample):
			print('Object dismissed:', sample)
			continue
		original_sample_detected, _ = malware_detection(sample, model, verbose=False)

	# Call evolution algorithm to find successful mutations
	population = gp.Population(size=size_population, length_sequence=number_perturbations)
	evasive_sequences = population.generation(file=sample, actions=ACTIONS, search_uap=search_UAP)

	# The check_exploration_set option was designed to evaluate the performance of specific evasive sequences
	# that are returned using the GP algorithm above. As opposed to the search_uap option, where the goal is
	# to identify a potential UAP, check_exploration_set is meant to verify the performance of one evasive
	# sequence across a larger number of files within the exploration set.
	uap_candidate_performance = {}
	if evasive_sequences and check_exploration_set:
		print("\n### Run UAP candidate on exploration set ###\n")

		current_potential_uap = 1
		for each_uap_tuple in evasive_sequences:
			uap_candidate = each_uap_tuple[0]  # E.g.: ([3, 3, 2, 2, 4], 126.263)
			uap_candidate_performance[str(uap_candidate)] = 0
			size_perturbation_vector = len(uap_candidate)

			# Picking sequentially each file from source folder
			current_file = 1
			for each_sample in sorted(os.listdir(EXPLORATION_SET)):

				# Convert selected sample into binaries
				sample = os.path.join(EXPLORATION_SET, each_sample)
				bin_bytes = f.readfile(sample)

				print('Running analysis for file {} of {}: {}\n'.format(current_file, len(os.listdir(EXPLORATION_SET)), sample))
				print('Injecting perturbations: {} -- Sequence {} of {}'.format(uap_candidate, current_potential_uap,
																				len(evasive_sequences)))
				inject_perturbation = size_perturbation_vector - 1
				mod_sample = f.rec_mod_files(bin_bytes, ACTIONS, uap_candidate, inject_perturbation)

				if cfg.file.getboolean('aimed', 'integrityCheck'):
					funcional, url_sandbox = malware_analysis(mod_sample, useVT, {})
				else:
					# When f.batch_functionality_test() is used instead of online verification
					funcional, url_sandbox = True, "www.no_integrity_test.com"

				# If modified file returns errors, label original & move to next
				if not mod_sample:
					os.rename(os.path.join(EXPLORATION_SET, each_sample), EXPLORATION_SET + 'LIEF_Error_' + each_sample)
					continue

				# Check if modified sample is detected
				print('Running detection..')
				detected, mod_sample_score = malware_detection(mod_sample, model)

				# Update dict with UAP candidate and the number of adversarial examples generated injecting the sequence
				if funcional and not detected:
					uap_candidate_performance[str(uap_candidate)] = uap_candidate_performance.get(str(uap_candidate), 0) + 1

				current_file += 1

			current_potential_uap += 1

		print('Adversarial performance of UAP candidates:', uap_candidate_performance)

	return evasive_sequences


def aimed_rl(base_path=None, report_path=None, train=False, evaluate=False):
	"""
		AIMED-RL: Automatic Intelligent Malware Modifications to Evade Detection
		with Reinforcement Learning.

		Input:
			base_path: path to RL optimizer, model, target model
			report_path: path to last RL reports
			train: set to train a new agent
			evaluate: set to evaluate existing agent
	"""

	print('\n### AIMED: Automatic Intelligent Malware Modifications to Evade Detection (RL) ###')

	if train:
		print("\nAIMED-RL Training Started")
		report_path = rl.train_and_save_agent(malware_detection=malware_detection,
											  malware_analysis=malware_analysis)

	if evaluate:
		print("\nAIMED-RL Evaluation Started")
		last_agent_path = base_path + 'agent/last/'
		evaluation_path = base_path + 'evaluation_set/'
		last_agent_information = report_path + 'AIMEDRL_training_report.csv'

		rl.load_and_evaluate_agent(directory_agent=last_agent_path,
								   agent_information=last_agent_information,
								   evaluation_set_directory=evaluation_path,
								   malware_detection=malware_detection,
								   malware_analysis=malware_analysis)


def armed(number_perturbations, rounds, files_expected, model):
	"""
		ARMED: Automatic Random Malware Modifications to Evade Detection
		This function injects n random perturbations to input PE malware
		in order to find adversarial examples.

		Input:
			number_perturbations: number of perturbations to inject
			rounds: number of rounds to run searching adversarial examples
			files_expected: number of malware files expected as output
			model: commercial AV or research malware classifier
	"""
	current_round = 1
	corrupt_samples = 0
	adversarial_samples = 0
	path = os.listdir(MALWARE_PATH)
	random.shuffle(path)

	for each_sample in path:

		sample = os.path.join(MALWARE_PATH, each_sample)

		# Skip file if it is labeled as problematic or not a file
		if 'error' in sample.lower() or not os.path.isfile(sample):
			current_round += 1
			continue

		# Convert selected sample into binaries
		bin_bytes = f.readfile(sample)

		# Create a vector with randomly chosen perturbations if none is given
		chosen_actions = f.create_random_actions(len(ACTIONS), number_perturbations)

		# Call a recursive function to inject n perturbations on a given sample
		print('\n### ARMED: Automatic Random Malware Modifications to Evade Detection # Round {} of {} ###\n'.
			  format(current_round, rounds))
		print('Processing: {}\n'.format(sample))
		# print('## ARMED # Round {} of {} ##\n'.format(current_round, rounds))
		inject_perturbation = number_perturbations - 1
		mod_sample = f.rec_mod_files(bin_bytes, ACTIONS, chosen_actions, inject_perturbation)

		# If modified sample returns errors, label original & move to next
		if not mod_sample:
			os.rename(sample, MALWARE_PATH + 'LIEF_Error_' + each_sample)
			current_round += 1
			continue

		# Calculate hashes from original and modified sample
		hash_sample = f.hash_files(sample)
		mod_sample_hash = f.hash_files(mod_sample)

		# Check whether original malware is detected
		print('## Malware Classifier: Original File ##\n')
		print('Running detection for:', each_sample)
		original_sample_detected, _ = malware_detection(sample, model)
		sample_report = {'positives': 1, 'total': 1}

		# Collect info to writeCSV function
		CSV = f.collect_info_CSV(sample, sample_report, number_perturbations, chosen_actions, mod_sample_hash,
								 hash_sample)

		# Only proceed if original malware is detected
		if original_sample_detected:
			if cfg.file.getboolean('armed', 'integrityCheck'):
				print('## Verification stage: Adversarial Example ##\n')
				print('Checking functionality of adversarial example:\n')
				funcional, url_sandbox = malware_analysis(mod_sample, useVT, CSV)
			else:
				# When f.batch_functionality_test() is used instead of online verification
				funcional, url_sandbox = True, "www.no_integrity_test.com"
		else:
			print('Original malware not detected by model. Skipping adversarial analysis.\n')
			current_round += 1
			continue

		# Check if adversarial example is detected
		print('## Malware Classifier: Adversarial Example ##\n')
		print('Injecting {} perturbation(s): {}\n'.format(number_perturbations, chosen_actions))
		print('Running detection for:', mod_sample)
		detected, mod_sample_score = malware_detection(mod_sample, model)

		# Save functional detected or adversarial examples in DB
		if funcional:
			mutation_name = str(number_perturbations) + '_m.exe'
			save_file_database(detected, mutation_name, url_sandbox, CSV, model)
			if not detected:
				adversarial_samples += 1
		else:
			corrupt_samples += 1

		# Every 100 files clean analyses to spare storage
		if cfg.file.getboolean('armed', 'integrityCheck') and current_round % 100 == 0:
			f.clean_cuckoo_analyses_folder()

		if adversarial_samples == files_expected or current_round >= rounds:
			break

		current_round += 1

	# Show results
	print('\n## Summary ##\n')
	print('Adversarial examples: {}'.format(adversarial_samples))
	print('Non-functional examples: {}'.format(corrupt_samples))

	return adversarial_samples, corrupt_samples


def armed2(number_perturbations, rounds, files_expected, model):
	"""
		ARMED-II: ARMED - Incremental Iterations
		This function injects random perturbations sequentially to input PE
		malware in order to find adversarial examples. After each injection,
		the malware mutation will be tested for functionality and evasion.

		Input:
			number_perturbations: number of perturbations to inject
			rounds: number of rounds to run when searching for evasions
			files_expected: number of malware mutations expected as output
			model: commercial AV or research malware classifier
	"""

	# Parse folder until find a malware sample that is detected to start
	print('\nSearch for random detected file as input object..')
	sample = None
	original_sample_detected = False
	while not original_sample_detected:
		sample = MALWARE_PATH + random.choice(os.listdir(MALWARE_PATH))
		# Skip file if it is labeled as problematic or not a file
		if 'error' in sample.lower() or not os.path.isfile(sample):
			print('Object dismissed:', sample)
			continue
		original_sample_detected, _ = malware_detection(sample, model)

	print('File classified as malware found: \n{}'.format(sample))

	# Convert selected sample into binaries
	bin_bytes = f.readfile(sample)

	# Check whether original malware is detected
	print('\n## Malware Classifier: Original File ##\n')
	print('Running detection for:\n', sample)
	original_sample_detected, _ = malware_detection(sample, model)
	sample_report = {'positives': 1, 'total': 1}

	# Make sure number of rounds is consistent with number of perturbations
	rounds = number_perturbations if number_perturbations != rounds else rounds

	new_mutations = 0
	for current_round in range(rounds):

		# Create random action and add it to sequence
		chosen_actions = f.create_random_actions(len(ACTIONS), current_round + 1)
		size_perturbation_vector = len(chosen_actions)

		print('\n### ARMED-II: Automatic Random Malware Modifications to Evade Detection ###\n')
		print('# Manipulation Box # Round {} # Perturbation {} of {} #\n'.format(current_round + 1, current_round + 1,
																				 number_perturbations))

		# Call a recursive function to inject x perturbations on a given sample
		print('Injecting {} perturbation(s): {}'.format(len(chosen_actions), chosen_actions))
		inject_perturbation = size_perturbation_vector - 1
		mod_sample = f.rec_mod_files(bin_bytes, ACTIONS, chosen_actions, inject_perturbation)

		# If modified sample returns errors, label original & move to next
		if not mod_sample:
			os.rename(sample, sample + '_LIEF_Error')
			current_round += 1
			continue

		# Calculate hashes from original and modified sample
		hash_sample = f.hash_files(sample)
		mod_sample_hash = f.hash_files(mod_sample)

		# Collect info to writeCSV function
		CSV = f.collect_info_CSV(sample, sample_report, current_round + 1, chosen_actions, mod_sample_hash, hash_sample)

		print('\n# Sandbox (Oracle) # Round {} # Perturbation {} of {} #'.format(current_round + 1, current_round + 1,
																				 number_perturbations))

		# Only proceed if original malware is detected
		print('\nChecking functionality of adversarial example:\n')
		if original_sample_detected:
			funcional, url_sandbox = malware_analysis(mod_sample, useVT, CSV)
		else:
			print('Original malware not detected by model. Skipping adversarial analysis.\n')
			break

		# Check if modified sample is detected
		print('## Malware Classifier: Adv. Example # Round {} of {} ##\n'.format(current_round + 1, rounds))
		print('Running detection for:', mod_sample)
		detected, mod_sample_score = malware_detection(mod_sample, model)

		# Save functional detected or adversarial examples in DB
		if funcional:
			mutation_name = str(size_perturbation_vector) + '_m.exe'
			save_file_database(detected, mutation_name, url_sandbox, CSV, model)
			if not detected:
				new_mutations += 1

		if new_mutations == files_expected:
			break

	# Show results
	print('\n## Summary ##\n')
	print('Evasive mutations found: {}'.format(new_mutations))

	return new_mutations


# COMPARING ARMED vs AIMED


def comparing(number_perturbations, rounds, files_expected, model):
	"""
		This function compares ARMED and AIMED to assess random vs evolutionary
		performance finding adversarial examples. The results will be stored on
		compare.csv.

		Important: If only one file needs to be compared select a folder with a
		unique malware example.

		Input:
			number_perturbations: number of perturbations to inject
			rounds: number of rounds to run when searching for evasions
			files_expected: number of malware mutations expected as output
			model: commercial AV or research malware classifier
	"""

	# Run ARMED
	start_Total = time()
	start_ARMED = time()
	ARMED_new_evasions, ARMED_corrupt_samples = armed(number_perturbations, rounds, files_expected, model)
	time_ARMED = f.time_me(start_ARMED)

	# Run AIMED
	size_population = 4
	start_AIMED = time()
	AIMED_new_evasions, AIMED_corrupt_samples = aimed(size_population, number_perturbations, model)
	time_AIMED = f.time_me(start_AIMED)

	# Update CSV with comparison data
	Compare_CSV = {}
	fields_compare = ['Sample', 'Perturbations', 'Module 1', 'Time M1', 'Files M1', 'Corr M1', 'Module 2', 'Time M2',
					  'Files M2', 'Corr M2', 'Total Time']
	Compare_CSV['Sample'], Compare_CSV['Perturbations'], Compare_CSV['Module 1'], Compare_CSV['Time M1'], Compare_CSV[
		'Files M1'], Compare_CSV['Corr M1'], Compare_CSV['Module 2'], Compare_CSV['Time M2'], Compare_CSV['Files M2'], \
	Compare_CSV['Corr M2'], Compare_CSV[
		'Total Time'] = 'Input object', number_perturbations, 'ARMED', time_ARMED, ARMED_new_evasions, \
						ARMED_corrupt_samples, 'AIMED', time_AIMED, AIMED_new_evasions, AIMED_corrupt_samples, strftime(
		'%H:%M:%S', gmtime(time() - start_Total))
	f.write_dict_CSV('db/compare.csv', Compare_CSV, fields_compare)

	# Update short version CSV with time averages to use as input in LaTeX
	f.comparing_AXMED()


# SAVE NEW MUTATIONS AND UPDATE DATABASE (ARMED / ARMED-II / AIMED)


def save_file_database(detected, mutation, url_sandbox, CSV, model, verbose=True):
	"""
		Structure manipulation and logic to update DB

		Input:
			detected: Boolean value whether malware mutation is detected
			mutation: Name of malware with path
			url_sandbox: URL to functionality report (default: Cuckoo sandbox)
			CSV: Structure to save in DB
			model: malware classifier
	"""

	# Ensure directories exist
	os.makedirs(os.path.dirname(MOD_PATH), exist_ok=True)
	os.makedirs(os.path.dirname(EVASION_PATH), exist_ok=True)
	os.makedirs(os.path.dirname(DETECTED_PATH), exist_ok=True)

	now = datetime.now()
	name_file = str(now.year) + str(now.month) + str(now.day) + str(now.hour) + str(now.minute) + str(now.second) + str(
		now.microsecond)

	if not detected:

		# Copy adversarial example into evasion path
		shutil.copyfile(MOD_PATH + mutation, EVASION_PATH + CSV['Perturbations'] + 'm_' + name_file + '.exe')

		# Update CSV with successful mutation
		CSV['Manipulated_File'], CSV['Full_Analysis_Report'], CSV['MF_Detections'], CSV['Full_Detections_Report'], CSV[
			'Date_Reported'] = EVASION_PATH + CSV[
			'Perturbations'] + 'm_' + name_file + '.exe', url_sandbox, 'Evasion', model, str(datetime.now())
		f.write_dict_CSV('db/evasion.csv', CSV, FIELDS)

		if verbose:
			print('Results: Evasion found for {}!\n'.format(model))
			# print('Evasive sequence: {}'.format(chosen_actions[:int(CSV['Perturbations'])]))

		return 1

	else:

		# Copy valid sample but detected into detected_path
		shutil.copyfile(MOD_PATH + mutation, DETECTED_PATH + CSV['Perturbations'] + 'm_' + name_file + '_' + model + '.exe')

		# Update CSV with valid mutation but detected by model
		CSV['Manipulated_File'], CSV['Full_Analysis_Report'], CSV['MF_Detections'], CSV['Full_Detections_Report'], CSV[
			'Date_Reported'] = DETECTED_PATH + CSV[
			'Perturbations'] + 'm_' + name_file + model + '.exe', url_sandbox, 'Detected', model, str(datetime.now())
		f.write_dict_CSV('db/detected.csv', CSV, FIELDS)

		return 0


# MALWARE ANALYSIS STAGE (LOCAL)


def malware_analysis(mod_sample, send_VT, CSV):
	"""
		Analyze malware with sandbox Cuckoo

		Input:
			mod_sample: Compiled version of modified malware mutation
			json_send: JSON status after sending mutation to local analysis
			send_VT: Boolean value indicating whether VirusTotal is used or detection will be performed locally
			CSV: Data structure with information to save on DB
	"""

	# Ensure directories exist
	os.makedirs(os.path.dirname(MOD_PATH), exist_ok=True)
	os.makedirs(os.path.dirname(FAIL_PATH), exist_ok=True)

	start = time()
	functionality = False

	# Send malware to sandbox
	if useHA:
		json_send = f.send_HA(mod_sample, 120)
	else:
		json_send = f.send_local_sandbox(mod_sample)

	# Show report from analysis sandbox: report URL + Job ID
	url_sample = 'http://localhost:8000/analysis/' + str(json_send['task_id']) + '/summary'
	# print('\nFull analysis report: {}\n\nStatus:'.format(url_sample))

	# If VM returns issues using sleep to space out requests to sandbox may help
	firstPrintR = True
	firstPrintW = True
	firstPrintRep = True
	while True:
		try:
			v = f.get_report_local_sandbox(json_send['task_id'], 'view')
			view_status = v['task']['status']
			if view_status == 'completed' and firstPrintRep:
				print('Analysis finished. Generating report..')
				firstPrintRep = False
			elif view_status == 'pending' and firstPrintW:
				print('Waiting in queue to be analyzed..')
				firstPrintW = False
			elif view_status == 'running' and firstPrintR:
				print('Analysis in progress..')
				firstPrintR = False
			elif view_status == 'reported':
				print('Report finished.')
				break
		# sleep(0.2)

		except (requests.ConnectionError, requests.Timeout, requests.ConnectTimeout) as e:
			print('Connection issues or API not available:\n{}'.format(e))

	# Check the likelihood that malware runs based on report
	err = 'CuckooPackageError: Unable to execute the initial process, analysis aborted.\n'
	r = f.get_report_local_sandbox(json_send['task_id'], 'report')
	report = r['debug']['cuckoo']
	duration = r['info']['duration']
	if err not in report and duration >= 15:
		functionality = True
		print('\nResults: Malware functional')

		# Show analysis time
		f.time_me(start)

		# Send to VT for detections (activate if local detection is not used)
		if send_VT:
			print('Sending to VirusTotal!')
			f.send_VT(mod_sample)

	elif err not in report and duration < 15:
		print('\nResults: It could not be determined (score = {} – duration = {})'.format(r['info']['score'], duration))

		# Show analysis time
		f.time_me(start)

	elif err in report:
		print('\nResults: Corrupt adversarial example')

		# Copy sample into failed path & tag with letter F
		now = datetime.now()
		name_file = str(now.year) + str(now.month) + str(now.day) + str(now.hour) + str(now.minute)
		shutil.copyfile(MOD_PATH + CSV['Perturbations'] + '_m.exe',
						FAIL_PATH + CSV['Perturbations'] + 'F_' + name_file + '.exe')

		# Update database with basic sample's info
		CSV['Manipulated_File'], CSV['Full_Analysis_Report'], CSV['Date_Reported'] = FAIL_PATH + CSV[
			'Perturbations'] + 'F_' + name_file + '.exe', url_sample, str(datetime.now())
		f.write_dict_CSV('db/corrupted.csv', CSV, FIELDS)

		# Show analysis time
		f.time_me(start)
	else:
		print("Malware analysis: No err and duration:", duration)

	return functionality, url_sample


# MALWARE ANALYSIS STAGE (REMOTE)


def malware_analysis_HA(mod_sample, json_send_HA, CSV):
	"""
		Analyze malware using remote service Hybrid Analysis
	"""

	loops = 0
	start = time()
	functionality = False

	# Wait a few minutes if server did not accept further submissions
	while json_send_HA == 429:
		print('Submission quota limit has been exceeded. Retry in 5 minutes.')
		sleep(301)

	# Retrieve report from Hybrid Analysis sandbox: report URL + Hash + Job ID
	url_sample = 'https://www.reverse.it/sample/' + json_send_HA['sha256'] + '/' + json_send_HA['job_id']
	print('\nFull report: {}\n\nStatus:'.format(url_sample))

	# Use loops and sleep to keep requests low and avoid API banned by HA (Limit: 5/m)
	limit = 30
	report_HA = None
	while loops < limit:
		try:
			# Server could return 403
			if f.url_ok(url_sample) == 200 or f.url_ok(url_sample) == 403:
				report_HA = f.get_report_HA(json_send_HA['sha256'])
				if report_HA['state'] == 'ERROR':
					print('The sandbox environment returned {}.'.format(report_HA['error_type']))
					break
				elif report_HA['state'] == 'IN_QUEUE':
					print('Waiting in queue to be analyzed. Next update in 60 s')
				elif report_HA['state'] == 'IN_PROGRESS':
					print('Analysis in progress..')
				elif report_HA['state'] == 'SUCCESS':
					print('Analysis finished.')
					break
				sleep(60)
			else:
				print('Website not reachable. Next update in 30 s')
				sleep(30)

			if loops == limit - 1:
				sys.exit('Environment exited because the limit of {} minutes has been reached.\n'.format(limit))

			loops += 1

		except (requests.ConnectionError, requests.Timeout, requests.ConnectTimeout) as e:
			print('Connection issues or API requests reached:\n{}'.format(e))

	# Check the likelihood that malware runs based on report
	if report_HA['domains'] or report_HA['compromised_hosts']:
		functionality = True
		print('\nResults: WORKING')
		print('Malware connects to domains or contacts hosts.')

		# Show analysis time
		f.time_me(start)

		# Send to VT to check detections
		print('Sending to VirusTotal!')
		f.send_VT(mod_sample)

	else:
		if report_HA['state'] != 'ERROR':
			print('\nResults: Most likely not working')
			print('Check if manipulated sample runs before scanning.')
			print('Malware does not connect to domains or contacts hosts.')

			# Copy sample into failed path & tag with F
			now = datetime.now()
			name_file = str(now.year) + str(now.month) + str(now.day) + str(now.hour) + str(now.minute)
			shutil.copyfile(MOD_PATH + CSV['Perturbations'] + '_m.exe',
							FAIL_PATH + CSV['Perturbations'] + 'F_' + name_file + '.exe')

			# Update database with basic sample's info
			CSV['Manipulated_File'], CSV['Full_Analysis_Report'] \
				= FAIL_PATH + CSV['Perturbations'] + 'F_' + name_file + '.exe', url_sample
			f.write_dict_CSV('db/fail_database.csv', CSV, FIELDS)

			# Show analysis time
			f.time_me(start)

	return functionality, url_sample


# MALWARE DETECTION STAGE (VIRUSTOTAL & METADEFENDER)


def malware_detection_VT(sample):
	"""
		Detecting malware samples using VirusTotal APIv3 (remote)

		Input:
			sample: malware that will be labeled
	"""

	try:
		# Get VirusTotal detections - Rescan: False
		file_hash = f.hash_files(sample)
		report = f.get_report_VT(file_hash, False)
		report_stats = report['data']['attributes']['last_analysis_stats']
		report_results = report['data']['attributes']['last_analysis_results']

		# Check reported status of sample
		detected = report_stats['malicious']
		undetected = report_stats['undetected']
		total = detected + undetected
		print('\nDetected by {} out of {} engines. \n'.format(detected, total))

		# Print only engines detecting new sample
		engines_detecting = {key: val for key, val in report_results.items() if val['category'] == 'malicious'}
		print(list(engines_detecting.keys()))

		# Label as malicious if most of engines do so
		detection = (1 if detected / total > 0.5 else 0)

		return detection

	except (requests.ConnectionError, requests.Timeout, requests.ConnectTimeout) as e:
		print('Connection issues or API requests threshold reached: {}'.format(e))


def malware_detection_MD(sample):
	"""
		Detecting malware samples using MetaDefender (remote)

		Input:
			sample: malware that will be labeled
	"""

	start = time()
	res = f.send_MD(sample)
	print('Mutation submitted \nId:', res['data_id'])
	ret = f.get_report_MD(res['data_id'])
	try:
		while ret['original_file']['progress_percentage'] < 100:
			sleep(10)
			ret = f.get_report_MD(res['data_id'])
			print('Progress:', ret['original_file']['progress_percentage'])

		print('Detections: {} out of {}'.format(ret['scan_results']
												['total_detected_avs'], ret['scan_results']['total_avs']))
		print('Time elapsed: {:.2f} s'.format(time() - start))
	except IOError:
		print('Error handling')


# MALWARE DETECTION STAGE (LOCAL)


def malware_detection(sample, model, threshold='', verbose=True):
	"""
		Detecting malware samples using local models.
		Using pre-trained model LightGBM: Trained with the EMBER
		Dataset containing 1+ million samples [Anderson et al. 2018],
		which reports AUC-ROC = 0.9991. A threshold of ~0.9 (0.896)
		corresponds to 92.128% detection rate at 0.074% FPR and 7.872% FNR.

		Input:
			sample: malware that will be labeled
			model: LGBM malware model or additional model using VM
			verbose: display whether file is detected as malware
	"""

	start = time()
	detect = False
	vm = "Windows7-Detection"
	loaded_model = f.load_av('data/lgbm_ember.pkl')

	# Pre-trained LightGBM Models available: (default) EMBER 2018 | SOREL 2020
	# SOREL: 0.9860 & EMBER: 0.8708 (AT: 0.8032) for FPR 0.1% | Default literature: 0.9 for 0.074% FPR
	if not threshold:
		if model == 'EMBER':
			threshold = .8708
		elif model == 'SOREL':
			threshold = .9860
			loaded_model = f.load_av('data/lgbm_sorel.pkl')
		elif model == 'EMBER_AT':
			threshold = .8032
			loaded_model = f.load_av('data/lgbm_ember_150k_ae_150k_mal_300k_ben_adv_trained_mixed.pkl')
		elif model == 'Add model via VM':
			# Start & restore the VM (headless = invisible)
			state = check_output(['VBoxManage', 'showvminfo', vm]).decode('UTF-8')
			if "powered off" in state or "saved" in state:
				call(['VBoxManage', 'snapshot', vm, 'restore', 'Windows7-' + model + '-Ready'])
				call(['VBoxManage', 'startvm', vm, '--type', 'headless'])
			elif "paused" in state:
				call(['VBoxManage', 'controlvm', vm, 'resume', '--type', 'headless'])

			# Pause the VM – Use pause only if power-off is on main()
			# call(['VBoxManage', 'controlvm', vm, 'pause', '--type', 'headless'])

			# Power off the VM
			call(['VBoxManage', 'controlvm', vm, 'poweroff'])

			# Show total time in hh:mm:ss
			f.time_me(start)

			return detect
		else:
			sys.exit('Models supported: LightGBM trained with EMBER or SOREL datasets')

	# Return detection using local model
	bin_bytes = f.readfile(sample)
	score = f.get_score_local(bin_bytes, loaded_model)
	if score > threshold:
		if verbose:
			print('\nMalware detected ({})\n'.format(round(score, 2)))
		return True, score
	else:
		if verbose:
			print('\nFile not detected ({})\n'.format(round(score, 2)))
		return False, score


# PERFORM FUNCTIONALITY TEST TO VERIFY POOL OF FILES


def batch_functionality_test(o_path, d_path):
	"""
		Evaluate functionality for a set of (adversarial) examples.

		Input:
			o_path: origin path to pool of malware to sample from
			d_path: destination path to save functional adversarial examples
	"""

	CSV = {}
	func_samples = 0
	count_samples = 0
	CSV['Perturbations'] = '10'
	len_path = len(os.listdir(o_path))
	for sample in os.listdir(o_path):

		# Select sample
		count_samples += 1
		print('Checking status of file:', sample)

		# Avoid re-checking functional adversarial example
		if sample in os.listdir(d_path):
			print('Integrity already verified. Moving to next file.')
			func_samples += 1
			continue

		# Run functionality test and manually fill number of perturbations for CSV
		func, _ = malware_analysis(mod_sample=o_path + sample, send_VT=False, CSV=CSV)

		if func:
			shutil.copyfile(o_path + sample, d_path + sample)
			func_samples += 1

		print('Sample {} out of {}: {} functional adversarial examples\n'.format(count_samples, len_path, func_samples))

		# Every 100 files clean analyses to spare storage
		if count_samples % 100 == 0:
			f.clean_cuckoo_analyses_folder()

		if count_samples >= len_path:
			return func_samples
