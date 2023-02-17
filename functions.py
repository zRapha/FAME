import os
import csv
import sys
import lief
import json
import time
import random
import shutil
import joblib
import zipfile
import lightgbm
import requests
import subprocess
import numpy as np
import pandas as pd
import config as cfg
from hashlib import sha256
import data.manipulate as m
from datetime import timedelta
from data.pefeatures import PEFeatureExtractor

VT_API_KEY = cfg.file['apiKeys']['vt']
HA_API_KEY = cfg.file['apiKeys']['ha']
MD_API_KEY = cfg.file['apiKeys']['md']

EXCEPTIONS = (MemoryError, lief.bad_file, lief.bad_format, lief.not_found)


def time_me(start_time):
	"""
		Timer returning output in following format HH:MM:SS
	"""
	# Show total time in hh:mm:ss
	minutes, seconds = divmod(time.time() - start_time, 60)
	hours, minutes = divmod(minutes, 60)
	print('\nProcessing time: %02d:%02d:%02d\n' % (hours, minutes, seconds))
	return '%02d:%02d:%02d' % (hours, minutes, seconds)


def readfile(filename):
	"""
		Convert file into bytes
	"""

	with open(filename, "rb") as b:
		b_bytes = b.read()
	return b_bytes


def unzip_file(zipped_path, unzipped_path):
	"""
		Unzip downloaded malware with standard industry password
	"""

	for item in os.listdir(zipped_path):
		if item.endswith(".zip"):
			full_path = zipped_path + item
			zip_file = zipfile.ZipFile(full_path, 'r')
			zip_file.setpassword(b"infected")  # Industry password for malware
			zip_file.extractall(unzipped_path)
			zip_file.close()


def hash_files(filename):
	"""
		Return SHA256 of a file
	"""

	h = sha256()
	with open(filename, 'rb', buffering=0) as f:
		for b in iter(lambda: f.read(128 * 1024), b''):
			h.update(b)
	return h.hexdigest()


def rename_files(files_path):
	"""
		Rename files with SHA256 value
	"""

	for item in os.listdir(files_path):
		files = files_path + item
		sha = hash_files(files)
		os.rename(files, files_path + sha)


def url_ok(url):
	"""
		Check URL status
	"""

	r = requests.get(url, timeout=10)
	return r.status_code


def create_sequential_actions(size_of_actions, n):
	"""
		Return vector filled with sequential perturbations
		e.g:
			for n = 4 and size_of_actions = 10

			[0, 0, 0, 0]
			[0, 0, 0, 1]
			[0, 0, 0, 2]
			...
			[9, 9, 9, 9]
	"""

	sequential_actions = []
	string_format_n = "{0:0" + str(n) + "}"
	cases_generated = [string_format_n.format(i) for i in range(size_of_actions ** n)]

	for i in range(len(cases_generated)):
		sequential_actions.append([int(s) for s in cases_generated[i]])

	return sequential_actions


def create_random_actions(size_of_actions, n):
	"""
		Return vector filled with random perturbations
	"""

	random.seed()
	random_actions = random.sample(range(size_of_actions), n)
	return random_actions


def actions_vector(actions_dict):
	"""
		Creating a dict with all available perturbations
	"""

	actions = {i: act for i, act in enumerate(actions_dict)}
	return actions


def build_bytes(input_bytes, total_number_perturbations):
	"""
		Compile a malware mutation after perturbations are injected

		Input:
			input_bytes: input malware in bytes
			total_number_perturbations: number of perturbations injected to keep track in name
	"""

	try:
		new_binary = lief.PE.parse(list(input_bytes))
		builder = lief.PE.Builder(new_binary)
		builder.build_imports(True)
		builder.patch_imports(True)
		builder.build()
		name_mod_file = cfg.file['paths']['mod'] + str(total_number_perturbations) + '_m.exe'
		builder.write(name_mod_file)

	except EXCEPTIONS as e:
		print("When parsing & building returned the following error:", str(e))
		return None

	return name_mod_file


def rec_mod_files(input_bytes, actions, chosen_actions, inject_perturbation):
	"""
		Recursive function to inject perturbations to input malware sample

		Input:
			input_bytes: input malware in bytes
			actions: all possible perturbations
			chosen_actions: vector of perturbations to inject
			inject_perturbation: perturbation being injected on this iteration
	"""

	if inject_perturbation == -1:
		return build_bytes(input_bytes, len(chosen_actions))
	else:
		try:
			manipulator = m.MalwareManipulator(input_bytes)
			next_action = actions[chosen_actions[inject_perturbation]]
			inject_action = manipulator.__getattribute__(next_action)
			mod_bytes = inject_action(input_bytes)

		except EXCEPTIONS as e:
			print('When injecting perturbation returned the error: ', e)
			return None

		return rec_mod_files(mod_bytes, actions, chosen_actions, inject_perturbation - 1)


# CALCULATE DIFFERENCE BETWEEN TWO PEs


def get_difference(sample1, sample2):
	"""
		Calculate the difference between two PE:

		Input:
			sample1: original sample S
			sample2: mutation S'
	"""

	s1_bytes = readfile(sample1)
	s2_bytes = readfile(sample2)
	try:
		# Use -n to compare only until smallest file ends to avoid EOF message
		compare_samples = subprocess.Popen(
			['cmp', '-l', '-n' + str(min(len(s1_bytes), len(s2_bytes))), sample1, sample2],
			stdout=subprocess.PIPE)
		out_compare_samples, err_compare_samples = compare_samples.communicate()

	except subprocess.CalledProcessError as e:
		raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))

	compare_samples.kill()
	return len(out_compare_samples)


# API MANAGEMENT: VIRUS TOTAL & HYBRID ANALYSIS & METADEFENDER


def check_API_key(api_key):
	"""
		Check whether an API key is given before using an external service
	"""
	if api_key == '':
		sys.exit('\nProvide an API key to use this service.\n')
	return 1


def get_user_quotas_VT():
	"""
		APIv3 implementation to get request quotas of user
	"""

	url = 'https://www.virustotal.com/api/v3/users'
	headers = {'x-apikey': VT_API_KEY, 'Accept': 'application/json'}
	response = requests.get(url + '/{}'.format(VT_API_KEY), headers=headers)
	json_response = response.json()
	request_rate = json_response['data']['attributes']['quotas']['api_requests_hourly']['allowed']
	return request_rate


def send_VT(sample):
	"""
		APIv3 implementation to send a file for analysis using VirusTotal

		Input:
			sample: malware that will be labeled
	"""

	# Check API key given
	check_API_key(VT_API_KEY)

	url = 'https://www.virustotal.com/api/v3/files'
	headers = {'x-apikey': VT_API_KEY, 'Accept': 'application/json'}
	files = {'file': (sample, open(sample, 'rb'))}
	response = requests.post(url, headers=headers, files=files)
	json_response = response.json()
	return json_response


def get_report_VT(file_hash, rescan=False):
	"""
		APIv3 implementation to retrieve report from a file analyzed using VirusTotal

		Input:
			file_hash: sample of malware to retrieve
			rescan: boolean option to rescan file in case it is previously detected
	"""

	# Check API key given
	check_API_key(VT_API_KEY)

	requests_allowed_minute = get_user_quotas_VT() / 60
	url = 'https://www.virustotal.com/api/v3/files'
	headers = {'x-apikey': VT_API_KEY, 'Accept': 'application/json'}
	querystring = {'limit': '10'}

	if rescan:
		response = requests.post(url + '/{}/analyse'.format(file_hash), headers=headers, params=querystring)
		return response.json()
	else:
		attempts = 0
		while attempts < requests_allowed_minute:

			response = requests.get(url + '/{}'.format(file_hash), headers=headers, params=querystring)

			if response.status_code == 404:
				time_to_sleep = (1 if 60 / requests_allowed_minute < 1 else 60 / requests_allowed_minute)
				print("Sample is not on VirusTotal. Waiting {} s..".format(time_to_sleep))
				time.sleep(time_to_sleep)

			elif response.status_code != 200:
				print(
					'\nVirusTotal returned server error {} while requesting scan report. Probably API issues. Exiting '
					'application until solved.\n'.format(
						response.status_code))
				sys.exit()

			else:
				json_response = response.json()
				return json_response

			attempts += 1

		sys.exit("VirusTotal processing is taking too long. Timing out.")


def get_report_VT_ext(file_hash, json_dest_path):
	"""
		Detecting malware samples using VirusTotal APIv3 (remote)

		Input:
			sample_report: the number of VT detections to use as benchmark
	"""

	print('\nDetection for sample:', file_hash)

	try:
		# Get VirusTotal detections - Rescan: False
		report = get_report_VT(file_hash, False)
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

		# Provide link to sample detections report
		# print('\n{}'.format(report['data']['links']['self']))

		# Save json file
		with open(json_dest_path.format(file_hash), 'w') as json_file:
			json.dump(report, json_file)

		return detection

	except (requests.ConnectionError, requests.Timeout, requests.ConnectTimeout) as e:
		print('Connection issues or API requests threshold reached: {}'.format(e))


def send_MD(sample):
	"""
		APIv2 implementation to send a file for analysis using MetaDefender

		Input:
			sample: malware that will be labeled
	"""

	# Check API key given
	check_API_key(MD_API_KEY)

	headers = {'apikey': MD_API_KEY}
	files = {'file': (sample, open(sample, 'rb'))}
	response = requests.post('https://api.metadefender.com/v2/file', headers=headers, files=files)
	json_response = response.json()
	return json_response


def get_report_MD(data_id):
	"""
		APIv2 implementation to retrieve report from a file analyzed using MetaDefender
	"""

	# Check API key given
	check_API_key(MD_API_KEY)

	headers = {'apikey': MD_API_KEY}
	response = requests.get('https://api.metadefender.com/v2/file/' + data_id, headers=headers)
	json_response = response.json()
	return json_response


def send_HA(sample, environment_id):
	"""
		APIv2 implementation to send a file for analysis using Hybrid Analysis

		Input:
			sample: malware that will be labeled
			environment_id: OS used to run malware sample (ID = 120: Windows7 - 64 bits)
	"""

	# Check API key given
	check_API_key(HA_API_KEY)

	f = open(sample, 'rb')
	headers = {'User-agent': 'Falcon Sandbox', 'api-key': HA_API_KEY}
	data = {'environment_id': environment_id, 'no_share_third_party': True, 'allow_community_access': False}
	files = {'file': f}

	try:
		submitUrl = 'https://www.hybrid-analysis.com/api/v2/submit/file'
		res = requests.post(submitUrl, headers=headers, data=data, files=files)
		if res.status_code == 200 or res.status_code == 201:
			print("\nFile successfully submitted to analysis: {}".format(os.path.basename(sample)))
			f.close()
			return res.json()
		else:
			print("Error code: {}, returned when uploading: {}".format(res.status_code, f.name))
			return res.status_code

	except requests.exceptions.HTTPError as err:
		print(err.read())
		err.print_exc()


def get_report_HA(file_hash):
	"""
		APIv2 implementation to retrieve report from a file analyzed using Hybrid Analysis
	"""

	# Check API key given
	check_API_key(HA_API_KEY)

	# Adjusted the API from params to headers to send the api-key
	headers = {'User-agent': 'Falcon Sandbox', 'api-key': HA_API_KEY}
	# EnvironmentID = 120 and needs to be implemented as '%3A120'
	res = requests.get('https://www.hybrid-analysis.com/api/v2/report/' + file_hash + '%3A120' + '/summary',
					   headers=headers)
	json_res = res.json()
	return json_res


# API MANAGEMENT: LOCAL SANDBOX (CUCKOO)


def send_local_sandbox(sample):
	"""
		API implementation to send a file for analysis using Cuckoo sandbox (local)

		Input:
			sample: malware that will be labeled
	"""

	submitUrl = "http://localhost:8090/tasks/create/file"
	data = {'timeout': '30'}
	with open(sample, "rb") as sample:
		files = {"file": ("new_mutation", sample)}
		r = requests.post(submitUrl, data=data, files=files)

	try:
		if r.status_code == 200:
			# print("\nFile successfully submitted to analysis: {}".format(os.path.basename(sample)))
			sample.close()
			return r.json()
		else:
			print("Error code: {}, returned when submitting.".format(r.status_code))
			return r.status_code

	except requests.exceptions.HTTPError as err:
		print(err.read())
		err.print_exc()


def get_report_local_sandbox(id_report, option):
	"""
		API implementation to retrieve report from a file analyzed using the Cuckoo sandbox
	"""

	# Options: view = short report | report = extensive report
	if option == 'view':
		r = requests.get('http://localhost:8090/tasks/view/' + str(id_report))
	else:
		r = requests.get('http://localhost:8090/tasks/report/' + str(id_report))
	return r.json()


# DATABASE.CSV CREATION & UPDATE


def collect_info_CSV(sample, sample_report, number_perturbations, chosen_actions, mod_sample_hash, hash_sample):
	"""
		Collect info on dict and prepare to save on CSV

		Input:
			sample: name of malware mutation
			sample_report: detection rate of mutation (positive/total detections)
			number_perturbations: number of perturbations injected
			chosen_actions: vector with perturbations injected to create malware mutation
			mod_sample_hash: SHA256 value of malware mutation
			hash_sample: SHA256 value of original malware provided as input
	"""

	CSV = {'Original_File': sample, 'OF_Detections': str(sample_report['positives']) + '/' + str(
		sample_report['total']), 'Perturbations': str(number_perturbations),
		   'Perturbations_Injected': chosen_actions[:number_perturbations], 'Mod_File_Hash': mod_sample_hash,
		   'Original_File_Hash': hash_sample}
	return CSV


def write_dict_CSV(csv_file, CSV, fields):
	"""
		Function to save dict into CSV file

		Input:
			csv_file: CSV file to create
			CSV: dict with values to store
			fields: pre-defined column names
	"""

	try:
		if not os.path.isfile(csv_file):
			with open(csv_file, 'w') as fi:
				writer = csv.DictWriter(fi, fieldnames=fields)
				writer.writeheader()
				writer.writerow(CSV)
		else:
			with open(csv_file, 'a') as fi:
				writer = csv.DictWriter(fi, fieldnames=fields, extrasaction='ignore')
				writer.writerow(CSV)

	except IOError as err:
		print("Exception: {}".format(err))


# 			TABLE CREATION FOR COMPARISON BETWEEN ARMED & AIMED


def time_to_seconds(data, new_df_cols=None, original_csv_cols=None):
	"""
		Convert time in data.csv from hh:mm:ss to s

		Input:
			data: input CSV file
			new_df_cols: columns for new dataframe used for format conversion (optional)
			original_csv_cols: pre-defined columns in original input CSV (optional)
	"""

	if new_df_cols is None:
		new_df_cols = ['Perturbations', 'Files M1', 'Time M1', 'Time M2']
	if original_csv_cols is None:
		original_csv_cols = ['Sample', 'Perturbations', 'Module 1', 'Time M1', 'Files M1', 'Corr M1', 'Module 2',
							 'Time M2', 'Files M2', 'Corr M2', 'Total Time']
	time_seconds = pd.DataFrame(columns=new_df_cols)
	csv_panda = pd.read_csv(data, names=original_csv_cols)
	for i in range(1, len(csv_panda)):
		x = time.strptime(csv_panda['Time M1'][i].split(',')[0], '%H:%M:%S')
		y = time.strptime(csv_panda['Time M2'][i].split(',')[0], '%H:%M:%S')
		time_seconds.loc[len(time_seconds)] = [csv_panda['Perturbations'][i], csv_panda['Files M1'][i],
											   timedelta(hours=x.tm_hour, minutes=x.tm_min,
														 seconds=x.tm_sec).total_seconds(),
											   timedelta(hours=y.tm_hour, minutes=y.tm_min,
														 seconds=y.tm_sec).total_seconds()]

	return time_seconds


def sum_times(data, col_time):
	"""
		Calculate from data the sum of time elapsed processing ARMED & AIMED

		Input:
			data: pd.Dataframe with time information
			col_time: column with time values (e.g., col_time='Time M1')
	"""

	sum_time_elapsed = {}
	for i in range(1, len(data)):
		if (data['Files M1'][i]) in sum_time_elapsed.keys():
			ext_sum = sum_time_elapsed[(data['Files M1'][i])] + data[col_time][i]
			sum_time_elapsed.update({(data['Files M1'][i]): ext_sum})
		else:
			sum_time_elapsed[(data['Files M1'][i])] = data['Time M1'][i]

	return sum_time_elapsed


def average_times(number_files_grouped_AXMED, sum_times_files_ARMED, sum_times_files_AIMED, csv_file=None, save=False):
	"""
		Create dict with number of mutations generated and time processed in average
		for ARMED (column 1) and AIMED (column 2)

		Input:
			number_files_grouped_AXMED: group with sum of all instances of times with same number of files created
			sum_times_files_ARMED: sum of all instances of times with same number of files created for ARMED
			sum_times_files_AIMED: sum of all instances of times with same number of files created for AIMED
			csv_file: input csv file (optional)
			save: boolean value to confirm whether to save results (default: False)
	"""

	average_times_ARMED = {}
	average_times_AIMED = {}
	for k, v in sum_times_files_ARMED.items():
		average_times_ARMED.update({k: round(sum_times_files_ARMED[k] / number_files_grouped_AXMED[k])})
		average_times_AIMED.update({k: round(sum_times_files_AIMED[k] / number_files_grouped_AXMED[k])})

	# Convert all items, keys (strings) and values (pd.Dataframe) to int
	average_times_ARMED = {int(k): int(v) for k, v in average_times_ARMED.items()}
	average_times_AIMED = {int(k): int(v) for k, v in average_times_AIMED.items()}

	list_avg_times_ARMED = sorted(average_times_ARMED.items())
	list_avg_times_AIMED = sorted(average_times_AIMED.items())

	if save:
		with open('support_armed_times.csv', 'a') as f:
			writer = csv.writer(f)
			for row_i in list_avg_times_ARMED:
				writer.writerow(row_i)
			f.close()

		# Remove existing file to avoid adding duplicated data
		if os.path.exists(csv_file):
			os.remove(csv_file)

		i = 0
		with open('support_armed_times.csv', 'r') as fin:
			with open(csv_file, 'a') as file_out:
				writer = csv.writer(file_out)
				for row in csv.reader(fin):
					writer.writerow(row + [list_avg_times_AIMED[i][1]])
					i += 1
				fin.close()
				file_out.close()

		# armed_times.csv is used as support to create csv_file with ARMED & AIMED times
		os.remove('support_armed_times.csv')

	return average_times_ARMED, average_times_AIMED


def comparing_AXMED():
	"""
		Create a CSV to be used directly in LaTeX with comparison between
		processing times of ARMED & AIMED
	"""

	# Prepare data to compare processing times between ARMED & AIMED
	AXMED_seconds = time_to_seconds('db/compare.csv')

	# Sum all instances of times with same number of files created
	sum_times_files_ARMED = sum_times(AXMED_seconds, 'Time M1')
	sum_times_files_AIMED = sum_times(AXMED_seconds, 'Time M2')

	# Group all lines with the same value of files / mutations generated
	number_files_grouped_AXMED = AXMED_seconds.groupby('Files M1').size()

	# Retrieve a csv file with 3 columns: 1) files generated 2) times ARMED and 3) times AIMED
	average_times(number_files_grouped_AXMED, sum_times_files_ARMED, sum_times_files_AIMED,
				  csv_file='db/compare_armed_aimed.csv', save=True)


# 			GET MALWARE SCORE USING PRE-TRAINED MODELS

def load_av(filename):
	"""
		Load pre-saved model (lgb or pickle).

		Input:
			filename: model with .pkl extension
	"""
	# Convert to joblib (.pkl) if lgb model (.txt) in the input
	if filename.endswith(".txt"):
		bst = lightgbm.Booster(model_file=filename)
		new_filename = filename[:-4] + ".pkl"
		joblib.dump(bst, new_filename)
		loaded_model = joblib.load(new_filename)
	else:
		loaded_model = joblib.load(filename)
	return loaded_model


def get_score_local(sample_bytes, model, top_features_path=''):
	"""
		Extract features from malware and get score using pre-saved model
		Ver.2: PEFeatureExtractor from EMBER dataset with 2381 features

		Input:
			sample_bytes: malware example
			model: ML-based model (i.e., LightGBM)
			top_features_path: path to NPZ with index of top features (Optional)
	"""

	# Handle LightGBM exception if different version of features used during training & testing (v1=2351 & v2=2381)
	if model.num_feature() == 2351:
		feature_extractor = PEFeatureExtractor(feature_version=1)
	elif model.num_feature() == 2381:
		feature_extractor = PEFeatureExtractor(feature_version=2)
	else:
		sys.exit('Number of features known are v1:2351 and v2:2381. Features detected: {}'.format(model.num_feature()))

	# Extract features of adversarial example
	features = feature_extractor.feature_vector(sample_bytes)

	# Optionally: Get score using reduced number of features (based on top20% of highest modified features of Logit model)
	if len(top_features_path) > 0:
		top_features = np.load(top_features_path)
		features = features[top_features['arr_0']]

	# Get malicious score from a single malware example
	score = model.predict([features])[0]

	return score


# UAP related modules: Convert problem-space to feature-space dataset, exploration set, etc.


def save_features_malware(csv_path, features_path, pert_vector):
	"""
		Saving features from adversarial examples (=evasion) of problem-space malware

		Input:
			csv_path: path to the CSV file
			features_path: path to the extracted features from files
			pert_vector: perturbation vector injected
	"""

	feature_extractor = PEFeatureExtractor()
	orig_features = []
	mod_features = []

	with open(csv_path + 'evasion.csv') as csv_file:

		dict_read = csv.DictReader(csv_file)
		for row in dict_read:

			# Ignoring malware with LIEF errors
			if row['Original_File'][21:25] == 'LIEF':
				continue

			# print(row['Original_File'], row['Manipulated_File'])

			try:
				orig_bin_bytes = readfile(row['Original_File'])
				mod_bin_bytes = readfile(row['Manipulated_File'])
			except OSError as e:
				print(e)

			orig_current_features = np.array(feature_extractor.feature_vector(orig_bin_bytes), dtype=np.float32)
			mod_current_features = np.array(feature_extractor.feature_vector(mod_bin_bytes), dtype=np.float32)

			orig_features.append(orig_current_features)
			mod_features.append(mod_current_features)

		orig_features = np.array(orig_features)
		mod_features = np.array(mod_features)

	np.savez_compressed(features_path + 'orig_files_uap_compress'.format(pert_vector), features=orig_features)
	np.savez_compressed(features_path + 'adv_examples_uap_compress'.format(pert_vector), features=mod_features)

	orig_loaded = np.load(features_path + 'orig_files_uap_compress.npz'.format(pert_vector))
	mod_loaded = np.load(features_path + 'adv_examples_uap_compress.npz'.format(pert_vector))

	# print('\nFeatures from original & modified problem-space malware saved.\n')
	# print('Orig:', orig_loaded['features'], len(orig_loaded['features']))
	# print('Mod:', mod_loaded['features'], len(mod_loaded['features']))

	assert np.array_equal(orig_features, orig_loaded['features']), 'Different sizes!'
	assert np.array_equal(mod_features, mod_loaded['features']), 'Different sizes!'


# print('\nCompressed and original versions are equal in size: Checked')


def copy_files_csv(csv_path='', dest_path=''):
	"""
		Copying specific examples by parsing (adversarial | detected | corrupt)
		CSV files.

		Input:
			csv_path: path to the CSV file
			dest_path: destination path
	"""
	# Ensure directory exist
	os.makedirs(os.path.dirname(dest_path), exist_ok=True)

	file_counter = 0
	with open(csv_path) as csv_file:
		dict_read = csv.DictReader(csv_file)
		for row in dict_read:
			print(row['Original_File'], row['Manipulated_File'])
			shutil.copyfile(row['Original_File'], dest_path + str(file_counter))
			file_counter += 1


def create_exploration_validation_set(o_path='', e_path='', v_path='', threshold=0.9, model='data/lgbm_ember.pkl'):
	"""
		Create exploration & validation sets to use during greedy-process of UAP search.

		Input:
			o_path: origin path, pool of malware to sample from
			e_path: exploration path
			v_path: validation path
	"""
	exploration_files = 100
	validation_files = 1000

	# Ensure directories exist
	os.makedirs(os.path.dirname(e_path), exist_ok=True)
	os.makedirs(os.path.dirname(v_path), exist_ok=True)

	# Load LightGBM model
	av_model = load_av(model)

	number_samples = 0
	for sample in os.listdir(o_path):
		bin_bytes = readfile(o_path + sample)
		score = get_score_local(bin_bytes, av_model)

		# Collect {validation_files} *different* detected samples for UAP process
		if number_samples < validation_files:
			if score > threshold:
				number_samples += 1
				shutil.copyfile(o_path + sample, v_path + sample)
				print('Validation set: Malware {} detected & copied ({})'.format(number_samples, round(score, 2)))

		# Collect {exploration_files} *different* detected samples for UAP process
		elif validation_files <= number_samples < exploration_files + validation_files:
			if score > threshold and sample not in os.listdir(v_path):
				number_samples += 1
				shutil.copyfile(o_path + sample, e_path + sample)
				print('Exploration set: Malware {} detected & copied ({})'.format(number_samples-validation_files, round(score, 2)))
		else:
			sys.exit('\nExploration & Validation sets correctly created.')


def clean_cuckoo_analyses_folder(path='.cuckoo/storage/analyses'):
	"""
		Delete analysis folder to spare storage.

		Input:
			path: [default] path to Cuckoo
	"""

	path_analyses = os.path.join(os.path.expanduser('~'), path)
	for file in sorted(os.listdir(path_analyses))[:-5]:
		filename = os.path.join(path_analyses, file)
		shutil.rmtree(filename)
	return
