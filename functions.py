import os
import csv
import lief # pip install lief==0.9.0
import random
import zipfile
import requests
import subprocess
import pandas as pd
from hashlib import sha256
from shutil import copyfile
import data.manipulate as m
from time import time, strptime
from sklearn.externals import joblib 
from argparse import ArgumentTypeError
from datetime import datetime, timedelta 
from data.pefeatures import PEFeatureExtractor


path = "samples/"
mod_path = "samples/mod/"
zipped_path = "samples/zipped/"
unzipped_path = "samples/unzipped/"
evasion_path = "samples/successful/"

LIEF_EXCEPTIONS = (lief.bad_file, lief.bad_format)

def time_me(start_time):
	'''
		Timer returning output in following format HH:MM:SS
	'''
	# Show total time in hh:mm:ss
	m, s = divmod(time() - start_time, 60)
	h, m = divmod(m, 60)
	print('\nTotal processing time: %02d:%02d:%02d\n' % (h, m, s))
	return '%02d:%02d:%02d' % (h, m, s)

def readfile(filename):
	'''
		Convert file into bytes
	'''
    
	with open(filename, "rb") as b:
		b_bytes = b.read()
	return b_bytes

def unzip_file(zipped_path, unzipped_path):
	'''
		Unzip downloaded malware with standard industry password
	'''
	
	for item in os.listdir(zipped_path):
		if item.endswith(".zip"):
			full_path = zipped_path + item
			zip_file = zipfile.ZipFile(full_path, 'r')
			zip_file.setpassword(b"infected") # Pass for malware
			zip_file.extractall(unzipped_path)
			zip_file.close()

def hash_files(filename):
	'''
		Return SHA256 of a file
	'''
		
	h = sha256()
	with open(filename, 'rb', buffering=0) as f:
		for b in iter(lambda : f.read(128*1024), b''):
			h.update(b)
	return h.hexdigest()

def rename_files(unzipped_path):
	'''
		Rename files with SHA256 value
	'''
	
	for item in os.listdir(unzipped_path):
		files = unzipped_path + item
		sha = hash_files(files)
		os.rename(files, unzipped_path + sha)

def url_ok(url):
	'''
		Check URL status 
	'''
	
	r = requests.get(url, timeout=10)
	return r.status_code
	

def create_random_actions(size_of_actions, n):
	'''
		Return vector filled with random perturbations
	'''
	
	random.seed() 
	random_actions = random.sample(range(size_of_actions), n)
	print("Actions:", random_actions)
	return random_actions
	
def actions_vector(actions_dict): 
	'''
		Creating a dict with all available perturbations
	'''
	
	actions = {i: act for i, act in enumerate(actions_dict)}
	return actions	

def build_bytes(input_bytes, pert_number): 
	'''
		Compile a malware mutations after perturbations are injected
		
		Input: 
			input_bytes: input malware in bytes
			pert_number: number of perturbations injected to keep track in name
	'''
	try: 
		new_binary = lief.PE.parse(list(input_bytes))

	except LIEF_EXCEPTIONS as e:
		print("No PE file created as LIEF returned:", str(e))
		return None
	
	new_binary = lief.PE.parse(input_bytes)
	builder = lief.PE.Builder(new_binary)
	builder.build_imports(True) 
	builder.patch_imports(True) 
	builder.build()
	name_mod_file = mod_path+str(pert_number)+'_m.exe'
	builder.write(name_mod_file) 
	return name_mod_file 

def rec_mod_files(input_bytes, actions, chosen_actions, perturbs, pert_number):
	'''
		Recursive function to inject perturbations to input malware sample
		
		Input: 
			input_bytes: input malware in bytes 
			actions: all possible perturbations 
			chosen_actions: vector of perturbations to inject
			perturbs: number of perturbation being injected on this iteration
			pert_number: total number of perturbations to inject
	'''
	
	if perturbs == -1: 
		return build_bytes(input_bytes, pert_number)
	else: 
		try:
			# Create an instance of MwManip (manipulate.py)
			malman = m.MalwareManipulator(input_bytes)
			# Call one by one all chosen_actions from n to 0
			#print("Perturbation: {} – Perform action: {}".format(perturbs, actions[chosen_actions[perturbs]]))
			function = ('malman.' + actions[chosen_actions[perturbs]])
			# Inject perturbation (check for overhead)
			mod_bytes = eval(function)(input_bytes)
		except lief.bad_format as e:
			print('LIEF returned the following error: ', e)

		return rec_mod_files(mod_bytes, actions, chosen_actions, perturbs-1, pert_number)

#				CALCULATE DIFFERENCE BETWEEN TWO PEs

def get_difference(sample1, sample2):
	''' 
		Calculate the difference between two PE: 
		
		Input: 
			sample1: original sample S 
			sample2: mutation S' 
	'''	
	
	s1_bytes = readfile(sample1)
	s2_bytes = readfile(mod_path+sample2) 
	try:
		# Use -n to compare only until smallest file ends to avoid EOF message		   
		compare_samples = subprocess.Popen(
			['cmp', '-l', '-n'+str(min(len(s1_bytes), len(s2_bytes))), sample1, mod_path+sample2],
			stdout=subprocess.PIPE)
		out_compare_samples, err_compare_samples = compare_samples.communicate()

	except subprocess.CalledProcessError as e:
		raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))

	#print('Time CMP: {} s'.format(round((time()-start_cmp), 2)))
	compare_samples.kill()
	return len(out_compare_samples)

#				API MANAGEMENT: VIRUS TOTAL & HYBRID ANALYSIS & METADEFENDER

def send_MD(myfile): 
	'''
		API implementation to send a file for analysis using MetaDefender 
	'''
	
	headers = {'apikey': '<YOUR_API_KEY>'}
	files = {'file': (myfile, open(myfile, 'rb'))}
	response = requests.post('https://api.metadefender.com/v2/file', headers=headers, files=files) 
	json_response = response.json()
	return json_response

def get_report_MD(data_id): 
	'''
		API implementation to retrieve report from a file analyzed using MetaDefender
	'''
	
	headers = {'apikey': '<YOUR_API_KEY>'}
	response = requests.get('https://api.metadefender.com/v2/file/'+data_id, headers=headers)
	json_response = response.json()
	return json_response


def send_VT(myfile): 
	'''
		API implementation to send a file for analysis using VirusTotal
	'''
	
	params = {'apikey': '<YOUR_API_KEY>'} 
	files = {'file': (myfile, open(myfile, 'rb'))}
	response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params) 
	json_response = response.json()
	return json_response

def get_report_VT(resource, rescan): 
	'''
		API implementation to retrieve report from a file analyzed using VirusTotal
		
		Input: 
			resource: sample of malware to retrieve
			rescan: boolean option to rescan file in case it is previously detected 
	'''
	
	params = {'apikey': '<YOUR_API_KEY>', 
	'resource': resource}
	headers = {"Accept-Encoding": "gzip, deflate",
			   "User-Agent" : "gzip,  My Python requests library example client or username"}
	if rescan == True: 
		response = requests.post('https://www.virustotal.com/vtapi/v2/file/rescan', params=params)
	else: 
		response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', 
		params=params, headers=headers)
		if response.status_code != 200: 
			print('\nVirusTotal returned server error {} while requesting scan report. Probably API issues. Exiting application until solved.\n'.format(response.status_code))
			quit()	
	json_response = response.json()
	return json_response

def get_summary_HA(sha256):
	'''
		API implementation to retrieve report from a file analyzed using Hybrid Analysis
	'''
	
	# Adjusted the API from params to headers to send the api-key
	headers = {'User-agent': 'Falcon Sandbox', 'api-key':
	'<YOUR_API_KEY>'}
	# EnvironmentID = 120 and needs to be implemented as '%3A120'
	res = requests.get('https://www.hybrid-analysis.com/api/v2/report/' 
	+ sha256 + '%3A120' + '/summary', headers=headers)
	json_res = res.json()
	return json_res

def send_HA(f_name, environmentid):
	'''
		API implementation to send a file for analysis using Hybrid Analysis
		
		Input: 
			f_name: malware sample 
			environmentid: OS used to run malware sample (ID = 120: Windows7 - 64 bits)
	'''
	
	f = open(f_name, 'rb')
	headers = {'User-agent': 'Falcon Sandbox', 'api-key':
	'<YOUR_API_KEY>'}
	data = {'environment_id': environmentid, 'no_share_third_party':True, 
	'allow_community_access':False}
	files = {'file': f}

	try:
		submitUrl = 'https://www.hybrid-analysis.com/api/v2/submit/file'
		res = requests.post(submitUrl, headers=headers, data=data, files=files) 
		if res.status_code == 200 or res.status_code == 201: 
			print("\nFile successfully submitted to analysis: {}".format(os.path.basename(f_name))) 
			return res.json()
		else:
			print("Error code: {}, returned when uploading: {}".format(res.status_code, f.name))
			return res.status_code
		f.close()
	
	except requests.exceptions.HTTPError: 
		print(err.read())
		traceback.print_exc()
		
		
#				API MANAGEMENT: LOCAL SANDBOX (CUCKOO)

		
def send_local_sandbox(f_name):
	'''
		API implementation to send a file for analysis using Cuckoo sandbox (local)
	'''
	
	submitUrl = "http://localhost:8090/tasks/create/file"
	data = {'timeout': '30'}
	with open(f_name, "rb") as sample:
		files = {"file": ("new_mutation", sample)}
		r = requests.post(submitUrl, data=data, files=files)

	try:
		if r.status_code == 200: 
			#print("\nFile successfully submitted to analysis: {}".format(os.path.basename(f_name)))
			return r.json()
		else:
			print("Error code: {}, returned when submitting: {}".format(res.status_code, f.name))
			return r.status_code
		sample.close()
	
	except requests.exceptions.HTTPError: 
		print(err.read())
		traceback.print_exc()
	
		
def get_summary_local_sandbox(id, option): 
	'''
		API implementation to retrieve report from a file analyzed using the Cuckoo sandbox
	'''
	
	# Options: view = short report | report = extensive report
	if option == 'view': 
		r = requests.get('http://localhost:8090/tasks/view/'+str(id))
	else: 
		r = requests.get('http://localhost:8090/tasks/report/'+str(id))	
	return r.json()


#				DATABASE.CSV CREATION & UPDATE

def collect_info_CSV(sample, sample_report, x, chosen_actions, mod_sample_hash, hash_sample): 
	'''
		Collect info on dict and prepare to save on CSV 
		
		Input: 
			sample: name of malware mutation 
			sample_report: detection rate of mutation (positive/total detections)
			x: number of perturbations injected
			chosen_actions: vector with perturbations injected to create malware mutation 
			mod_sample_hash: SHA256 value of malware mutation
			hash_sample: SHA256 value of original malware provided as input
	'''
	
	CSV = {}
	CSV['Original_File'], CSV['OF_Detections'], CSV['Perturbations'], CSV['Perturbations_Injected'], \
	CSV['Mod_File_Hash'], CSV['Original_File_Hash'], = sample, str(sample_report['positives']) +'/' \
	+str(sample_report['total']), str(x+1), chosen_actions[:x+1], mod_sample_hash, hash_sample 
	return CSV

def write_dict_CSV(csv_file, CSV, fields):
	'''
		Function to save dict into CSV file
		
		Input: 
			csv_file: CSV file to create
			CSV: dict with values to store 
			fields: pre-defined column names
	'''
	
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


#				TABLE CREATION FOR COMPARISON BETWEEN ARMED & AIMED


def time_to_seconds(data, new_df_cols=None, original_csv_cols=None): 
	''' 
		Convert time in data.csv from hh:mm:ss to s 
		
		Input: 
			data: input CSV file
			new_df_cols: columns for new dataframe used for format conversion (optional)
			original_csv_cols: pre-defined columns in original input CSV (optional)
	'''
	
	if new_df_cols is None: 
		new_df_cols = ['Perturbations', 'Files M1', 'Time M1', 'Time M2']
	if original_csv_cols is None: 
		original_csv_cols = ['Sample', 'Perturbations', 'Module 1', 'Time M1', \
		'Files M1', 'Corr M1', 'Module 2', 'Time M2', 'Files M2', 'Corr M2', 'Total Time']
	time_seconds = pd.DataFrame(columns=new_df_cols)
	csv_panda = pd.read_csv(data, names=original_csv_cols)
	for i in range(1,len(csv_panda)):
		x = strptime(csv_panda['Time M1'][i].split(',')[0],'%H:%M:%S')
		y = strptime(csv_panda['Time M2'][i].split(',')[0],'%H:%M:%S')
		time_seconds.loc[len(time_seconds)] = [csv_panda['Perturbations'][i], csv_panda['Files M1'][i], \
		timedelta(hours=x.tm_hour,minutes=x.tm_min,seconds=x.tm_sec).total_seconds(), \
		timedelta(hours=y.tm_hour,minutes=y.tm_min,seconds=y.tm_sec).total_seconds()]
		
	return time_seconds
	
def sum_times(data, col_time):
	''' 
		Calculate from data the sum of time elapsed processing ARMED & AIMED
		
		Input: 
			data: pd.Dataframe with time information 
			col_time: column with time values (e.g., col_time='Time M1') 
	'''
	
	sum_times = {}
	for i in range(1, len(data)): 
		if (data['Files M1'][i]) in sum_times.keys():
			ext_sum = sum_times[(data['Files M1'][i])] + data[col_time][i]
			sum_times.update({(data['Files M1'][i]): ext_sum})
		else:
			sum_times[(data['Files M1'][i])] = data['Time M1'][i]
	
	return sum_times
			
def average_times(number_files_grouped_AXMED, sum_times_files_ARMED, sum_times_files_AIMED, csv_file=None, save=False): 
	''' 
		Create dict with nuumber of mutations generated and time processed in average 
		for ARMED (column 1) and AIMED (column 2) 
		
		Input: 
			number_files_grouped_AXMED: group with sum of all instances of times with same number of files created
			sum_times_files_ARMED: sum of all instances of times with same number of files created for ARMED
			sum_times_files_AIMED: sum of all instances of times with same number of files created for AIMED
			csv_file: input csv file (optional)
			save: boolean value to confirm whether to save results (default: False)
	'''
	
	average_times_ARMED = {}
	average_times_AIMED = {}
	for k, v in sum_times_files_ARMED.items(): 
		average_times_ARMED.update({k: round(sum_times_files_ARMED[k] / number_files_grouped_AXMED[k])})
		average_times_AIMED.update({k: round(sum_times_files_AIMED[k] / number_files_grouped_AXMED[k])})

	# Convert all items, keys (strings) and values (pd.Dataframe) to int
	average_times_ARMED = {int(k):int(v) for k,v in average_times_ARMED.items()}
	average_times_AIMED = {int(k):int(v) for k,v in average_times_AIMED.items()}
	
	list_avg_times_ARMED = sorted(average_times_ARMED.items())
	list_avg_times_AIMED = sorted(average_times_AIMED.items())

	if save:
		with open('support_armed_times.csv', 'a') as f:
			writer = csv.writer(f) 
			for rowi in list_avg_times_ARMED:
				writer.writerow(rowi)
			f.close()
			
		# Remove existing file to avoid adding duplicated data
		if os.path.exists(csv_file): 
			os.remove(csv_file)
					
		i=0
		with open('support_armed_times.csv', 'r') as fin:
			with open(csv_file, 'a') as fout:		
				writer = csv.writer(fout)
				for row in csv.reader(fin):
					writer.writerow(row+[list_avg_times_AIMED[i][1]])
					i+=1
				fin.close()
				fout.close()
		
		# armed_times.csv is used as support to create csv_file with ARMED & AIMED times
		os.remove('support_armed_times.csv')	
			
	return average_times_ARMED, average_times_AIMED
	
def comparing_AXMED():
	'''
		Create a CSV to be used directly in LaTeX with comparison between 
		processing times of ARMED & AIMED 
	'''
	
	# Prepare data to compare processing times between ARMED & AIMED
	AXMED_seconds =  time_to_seconds('db/compare.csv')

	# Sum all instances of times with same number of files created
	sum_times_files_ARMED = sum_times(AXMED_seconds, 'Time M1')
	sum_times_files_AIMED = sum_times(AXMED_seconds, 'Time M2')
	
	# Group all lines with the same value of files / mutations generated
	number_files_grouped_AXMED = AXMED_seconds.groupby('Files M1').size()

	# Retrieve a csv file with 3 columns: 1) files generated 2) times ARMED and 3) times AIMED
	average_times(number_files_grouped_AXMED, sum_times_files_ARMED, sum_times_files_AIMED,  csv_file='db/compare_armed_aimed.csv', save=True)


#				GET SCORE OF MALICIOUSNESS USING PRE-SAVED MALWARE CLASSIFIER MODEL 

def load_av(filename): 
	''' 
		Load pre-saved model (filename = .pkl) 
	'''
	
	loaded_model = joblib.load(filename)
	return loaded_model
	
def get_score_local(bytez, local_model):
	''' 
		Extract features from malware and get score using pre-saved model 
	'''
	
	# Extract features -- len(features) = 2350
	feature_extractor =  PEFeatureExtractor() 
	features = feature_extractor.extract(bytez)

	# Get malicious score from a single sample
	score = local_model.predict_proba(features.reshape(1,-1))[0,-1] 
	return score

def str2bool(v):
	"""
	Required for parsing --flags from command line
	"""
	if isinstance(v, bool):
		return v
	if v.lower() in ('yes', 'true', 't', 'y', '1'):
		return True
	elif v.lower() in ('no', 'false', 'f', 'n', '0'):
		return False
	else:
		raise ArgumentTypeError('Boolean value expected.')
