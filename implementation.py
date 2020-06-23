import os
import gp
import json
import requests
import functions as f
from random import choice
from shutil import copyfile
import data.manipulate as m
from datetime import datetime   
from time import time, sleep, strftime, gmtime
from subprocess import call, check_output, CalledProcessError, Popen, PIPE


# Paths
mod_path = "samples/mod/"
fail_path = "samples/unsuccessful/"
evasion_path = "samples/successful/"
detected_path = "samples/successful/detected/"
unzipped_path = "samples/unzipped/"

# Default fields for database
fields = ['Original_File', 'OF_Detections', 'Manipulated_File', 'MF_Detections', 'Perturbations', 'Perturbations_Injected',
'Full_Detections_Report', 'Full_Analysis_Report', 'Mod_File_Hash', 'Original_File_Hash', 'Date_Reported']


#				HANDLE INPUT PARAMETERS


def handling_input(args): 
	'''
		Handle input entered on terminal when calling AXMED
	'''
	files_expected = detection_threshold = -1
	rounds = files_expected**3 if files_expected > 9 else 100
	sample = unzipped_path+choice(os.listdir(unzipped_path)) # random
	if len(args) <= 6:
		print('\nSelect random malware sample: \n{}'.format(sample))
		n = int(args[2])	
		files_expected = int(args[4])
	elif len(args) > 6:  
		n = int(args[2])
		if args[3] == '-r': 
			rounds = int(args[4])
		elif args[3] == '-m': 
			files_expected = int(args[4])
			if args[5] == '-r':
				rounds = int(args[6])
			else:
				rounds = files_expected**3 if files_expected > 9 else 100
		elif args[7] == '-t': 
			detection_threshold = int(args[8])
			rounds = 100
		if len(args) > 8: 
			if args[7] == '-m' and not args[5] == '-m': 
				files_expected = int(args[8])
				rounds = files_expected**3 if files_expected > 9 else 100
			elif args[7] == '-t' and not args[5] == '-t':
				detection_threshold = int(args[8])
				rounds = 100
			else: 
				raise ValueError('Argument not accepted: {} {}. Please check usage with -h'.\
				format(args[7], int(args[8])))
			if len(args) > 10:
				if args[9] == '-t' and not (args[7] == '-t' or args[7] == '-m' or \
				args[5] == '-t' or args[5] == '-m'): 
					detection_threshold = int(args[10])
					rounds = 100
				else: 
					raise ValueError('Arguments not accepted: {} {}. Please check usage with -h'.\
					format(args[9], int(args[10])))
					   		
	return sample, n, rounds, files_expected, detection_threshold


#				IMPLEMENTATION AIMED / ARMED FRAMEWORKS


def aimed(bin_bytes, sample, size_population, length_sequence, files_expected, scanner): 
	'''
		AIMED: Automatic Intelligent Malware Modifications to Evade Detection
		This function implements GP to find PE adversarial examples. 
		
		Input: 
			bin_bytes: binaries from input malware sample
			sample: malware sample in terminal
			size_population: population size for GP (Default: 4)
			length_sequence: length of perturbation sequence
			files_expected: number of malware mutations expected as output
			scanner: commercial AV or malware model classifier 
	'''
	
	# Create a dict with all perturbations
	actions = f.actions_vector(m.ACTION_TABLE.keys())
	
	# Inject children sequences to S to create four S'
	mutation = {}
	mutation['Malware_Bytes'], mutation['Malware_Sample'], mutation['Actions'], \
	mutation['Files_Expected'], mutation['hash_sample'], mutation['Scanner']= \
	bin_bytes, sample, actions, files_expected,  f.hash_files(sample), scanner
	
	# Call evolution algorithm to find successfull mutations 
	print('\n### AIMED: Automatic Intelligent Malware Modifications to Evade Detection ###')
	population = gp.Population(size=size_population, length_sequence=length_sequence, show_sequences=True)
	return population.generation(mutation=mutation)	

def armed(bin_bytes, sample, n, rounds, files_expected, detection_threshold, scanner): 
	'''
		ARMED: Automatic Random Malware Modifications to Evade Detection
		This function injects n random perturbations to input PE malware 
		in order to find adversarial examples. 
		
		Input: 
			bin_bytes: binaries from input malware sample
			sample: malware sample in terminal
			n: number of perturbations to inject
			rounds: number of rounds to run when searching for evasions
			files_expected: number of malware mutations expected as output
			detection_threshold: run until number of detections is below threshold (only for VirusTotal)
			scanner: commercial AV or malware model classifier 
	'''
    # Decide whether to use remote (VirusTotal) or local detection & remote or local sandbox
	useVT = False
	useHA = False

    # Iterate to generate -m mutations for all perturbations on the loop 
	start = time()
	max_number_perts = n
	while n <= max_number_perts:	
		new_samples = 0	
		new_corrupt_samples = 0		
		for r in range(rounds): 
			
            # Create a dict with all perturbations & choose random actions 
			actions = f.actions_vector(m.ACTION_TABLE.keys())
			chosen_actions = f.create_random_actions(len(actions), n)

            # Call a recursive function to inject n perturbations on a given sample
			print('\n### ARMED: Automatic Random Malware Modifications to Evade Detection ###\n')
			print('# Manipulation Box # Round {} of {} #\n'.format(r+1, rounds))
			perturbs = n-1
			start_pert = time()
			mod_sample = f.rec_mod_files(bin_bytes, actions, chosen_actions, perturbs, n)
			print('Time injecting perturbations: {} s'.format(round(time()-start_pert, 2))) 

            # Send the modified sample to sandbox to check functionality (not corrupt)
			print('\n# Sandbox (Oracle) # Round {} of {} #'.format(r+1, rounds))
            
            # Check if use remote or local sandbox
			if useHA: 
				json_send_HA = f.send_HA(mod_sample, 120) 
			else: 
				json_send = f.send_local_sandbox(mod_sample) 

            # Calculate hashes from original and modified sample
			hash_sample = f.hash_files(sample)
			mod_sample_hash = f.hash_files(mod_sample)

            # Get VT detections for original sample to use as benchmark
			if useVT:
			    sample_report = f.get_report_VT(hash_sample, rescan=False)
			else:
			    sample_report = {'positives': 49, 'total': 66} # Debug mode (without VT/offline)
            
            # Collect info to writeCSV function 
			CSV = f.collect_info_CSV(sample, sample_report, n-1, chosen_actions, mod_sample_hash, hash_sample)
	 
            # Malware analysis & malware detection stages
			funcional = False
			funcional, url_sandbox = malware_analysis(mod_sample, json_send, useVT, CSV) 
            
            # Check if use remote or local detection along with functionality 
			if useVT and funcional:  
				new_samples+=1
				CSV['Full_Analysis_Report'] = url_sandbox
				vt_positives = malware_detection_VT(sample_report, CSV)
				if vt_positives < detection_threshold:
					break
                    
			elif not useVT and funcional: 
				print('# Malware Classifier # Round {} # Perturbation {} of {} #\n'.format(r+1, int(CSV['Perturbations']), n))
            	# Check if mutation is detected
				start = time()
				mutation = CSV['Perturbations']+'_m.exe'
				print('Running detection for:', mutation) 
				detected = malware_detection(mutation, scanner)
				new_samples += save_file_database(detected, mutation, url_sandbox, CSV, scanner)
            	
			elif not funcional: 
				new_corrupt_samples += 1

            	
			if r == rounds-1: 
				print('\n## Summary ##')
                
			if new_samples == files_expected:
				break                
                
		print('Evasive mutations found: {}'.format(new_samples))
		print('Corrupt mutations found: {}'.format(new_corrupt_samples))
		n+=1
        
	return new_samples, new_corrupt_samples

def armed2(bin_bytes, sample, n, rounds, files_expected, scanner): 
	'''
		ARMED-II: Automatic Random Malware Modifications to Evade Detection -- Incremental Iterations
		This function injects random perturbations sequentially to input PE malware 
		in order to find adversarial examples. After each injection, the malware 
		mutation will be tested for functionality and evasion. 
		
		Input: 
			bin_bytes: binaries from input malware sample
			sample: malware sample in terminal
			n: number of perturbations to inject
			rounds: number of rounds to run when searching for evasions
			files_expected: number of malware mutations expected as output
			scanner: commercial AV or malware model classifier 
	'''
	# Decide whether to use remote (VirusTotal) or local detection
	useVT = False
	
	# Create a dict with all perturbations
	actions = f.actions_vector(m.ACTION_TABLE.keys())
	
	# Get VT detections for original sample to use as benchmark
	hash_sample = f.hash_files(sample)
	if useVT:
		sample_report = f.get_report_VT(hash_sample, rescan=False)
	else:
		sample_report = {'positives': 49, 'total': 66} # Debug mode (without VT/offline)
	
	# Inject perturbations and check for detection 
	chosen_actions = [None]*n
	new_mutations = 0
	for x in range(n):
		
		for r in range(rounds): 	
			
			# Create random action and add it to sequence 
			random_actions = f.create_random_actions(len(actions), x+1)
			chosen_actions[x] = random_actions[0]
			
			print('\n### ARMED-II: Automatic Random Malware Modifications to Evade Detection ###\n')
			print('# Manipulation Box # Round {} # Perturbation {} of {} #\n'.format(r+1, x+1, n))
			
			# Call a recursive function to inject x perturbations on a given sample (Print = Perturbation: x+1)
			mod_sample = f.rec_mod_files(bin_bytes, actions, chosen_actions, x, x+1)

			print('\n# Sandbox (Oracle) # Round {} # Perturbation {} of {} #'.format(r+1, x+1, n))

			# Send the modified sample to sandbox to check functionality (not corrupt)
			json_send = f.send_local_sandbox(mod_sample) 
			
			# Calculate hashes from original and modified sample 
			mod_sample_hash = f.hash_files(mod_sample)
			
			# Collect info to writeCSV function 
			CSV = f.collect_info_CSV(sample, sample_report, x, chosen_actions, mod_sample_hash, hash_sample)
			
			# Malware analysis & malware detection stages
			useVT=False 
			funcional = False
			funcional, url_sandbox = malware_analysis(mod_sample, json_send, useVT, CSV) 
			
			# Increase number of mutations to match -m given based on local checks 
			if funcional: 
				print('# Malware Classifier # Round {} # Perturbation {} of {} #\n'.format(r+1, int(CSV['Perturbations']), n))
            	#Check if mutations is detected
				start = time()
				mutation = CSV['Perturbations']+'_m.exe'
				print('Running detection for:', mutation) 
				detected = malware_detection(mutation, scanner)
				new_mutations += save_file_database(detected, mutation, url_sandbox, CSV, scanner)

			if new_mutations == files_expected: 
				break

	# Show time	
	print('Evasive mutations found: {}'.format(new_mutations))	
	
	
#				COMPARING ARMED vs AIMED 


def comparing(bin_bytes, sample, n, rounds, files_expected, detection_threshold, scanner): 
	'''
		This function compares ARMED and AIMED to assess random vs. evolutionary performance
		finding adversarial examples. The results will be stored on compare.csv
	'''
	
	# Run ARMED 
	start_Total = time()
	start_ARMED = time()
	_, ARMED_corrupt_samples = armed(bin_bytes, sample, n, rounds, files_expected, detection_threshold, scanner)
	time_ARMED = f.time_me(start_ARMED)
	
	# Run AIMED 
	size_population = 4
	start_AIMED = time()
	AIMED_new_evasions, AIMED_corrupt_files = aimed(bin_bytes, sample, size_population, n, files_expected, scanner)
	time_AIMED = f.time_me(start_AIMED)
	
	# Update CSV with comparison data 
	Compare_CSV = {}
	fields_compare = ['Sample', 'Perturbations', 'Module 1', 'Time M1', 'Files M1', 'Corr M1', 'Module 2', 'Time M2', 'Files M2', 'Corr M2', 'Total Time']
	Compare_CSV['Sample'], Compare_CSV['Perturbations'], Compare_CSV['Module 1'], Compare_CSV['Time M1'], Compare_CSV['Files M1'], \
	Compare_CSV['Corr M1'], Compare_CSV['Module 2'], Compare_CSV['Time M2'], Compare_CSV['Files M2'], Compare_CSV['Corr M2'], Compare_CSV['Total Time'] = \
	sample, n, 'ARMED', time_ARMED, files_expected, ARMED_corrupt_samples, 'AIMED', time_AIMED, AIMED_new_evasions, AIMED_corrupt_files, strftime('%H:%M:%S', gmtime(time() - start_Total))
	f.write_dict_CSV('db/compare.csv', Compare_CSV, fields_compare)  
	
	# Update short version CSV with time averages to use as input in LaTeX
	f.comparing_AXMED()
	

#				SAVE NEW MUTATIONS AND UPDATE DATABASE FOR ALL MODULES (ARMED / ARMED-II / AIMED)

	
def save_file_database(detected, mutation, url_sandbox, CSV, scanner): 
	'''
		Structure manipulation and logic to update DB	
		
		Input: 
			detected: Boolean value whether malware mutation is detected
			mutation: Name of malware with path 
			url_sandbox: URL to functionality report (default: Cuckoo sandbox)
			CSV: Structure to save in DB 
			scanner: malware classifier
	'''
	
	if not detected:
		
		# Copy successful sample into evasion path 
		now = datetime.now()
		name_file = str(now.year)+str(now.month)+str(now.day)+ \
		str(now.hour)+str(now.minute)+str(now.second)
		copyfile(mod_path+mutation, evasion_path+ \
		CSV['Perturbations']+'m_'+name_file+'.exe')
		
		# Update CSV with successful mutation
		CSV['Manipulated_File'], CSV['Full_Analysis_Report'], \
		CSV['MF_Detections'], CSV['Full_Detections_Report'], CSV['Date_Reported'] = \
		evasion_path+CSV['Perturbations']+'m_'+ name_file+'.exe', \
		url_sandbox, 'Evasion', scanner, str(datetime.now())
		f.write_dict_CSV('db/evasion.csv', CSV, fields) 

		print('Results: Evasion found for {}!\n'.format(scanner))
		#print('Evasive sequence: {}'.format(chosen_actions[:int(CSV['Perturbations'])]))
		
		return 1
	
	else: 
		
		# Copy valid sample but detected into detected_path 
		now = datetime.now()
		name_file = str(now.year)+str(now.month)+str(now.day)+ \
		str(now.hour)+str(now.minute)+str(now.second)
		copyfile(mod_path+mutation, detected_path+ \
		CSV['Perturbations']+'m_'+name_file+scanner+'.exe')
		
		# Update CSV with valid mutation but detected by scanner
		CSV['Manipulated_File'], CSV['Full_Analysis_Report'], \
		CSV['MF_Detections'], CSV['Full_Detections_Report'], CSV['Date_Reported'] = \
		detected_path+CSV['Perturbations']+'m_'+ name_file+scanner+'.exe', \
		url_sandbox, 'Detected', scanner, str(datetime.now())
		f.write_dict_CSV('db/detected.csv', CSV, fields) 
	
		return 0
	

#				MALWARE ANALYSIS STAGE (LOCAL)


def malware_analysis(mod_sample, json_send, useVT, CSV): 
	'''
		Analyze malware with sandbox Cuckoo
		
		Input: 
			mod_sample: Compiled version of modified malware mutation 
			json_send: JSON status after sending mutation to local sandbox for analysis
			useVT: Boolean value indicating whether VirusTotal is used or detection will be performed locally
			CSV: Data structure with information to save on DB 
	'''
	
	loops = 0
	start = time()
	functionality = False
	
	# Show report from analisys sandbox: report URL + Job ID
	url_sample = 'http://localhost:8000/analysis/' + str(json_send['task_id']) + '/summary'
	print('\nFull analysis report: {}\n\nStatus:'.format(url_sample))   
      
    # Using sleep in loop to space requests to sandbox may improve results
	firstPrintR, firstPrintW, firstPrintRep = True, True, True
	while True: 
		try: 
			v = f.get_summary_local_sandbox(json_send['task_id'], 'view')
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
			sleep(0.2)

		except (requests.ConnectionError, requests.Timeout, requests.ConnectTimeout) as e: 
			print('Connection issues or API not available:\n{}'.format(e)) 

    # Check the likelihood that malware runs based on report
	err = 'CuckooPackageError: Unable to execute the initial process, analysis aborted.\n'
	r = f.get_summary_local_sandbox(json_send['task_id'], 'report')
	report = r['debug']['cuckoo']
	duration = r['info']['duration']
	if err not in report and duration >= 15: 
		functionality = True
		print('\nResults: WORKING')
        
        # Show analysis time in hh:mh:ss
		f.time_me(start)

		# Send to VT for detections (activate if local detection is not used)
		if useVT:
		    print('Sending to VirusTotal!')
		    json_send_VT = f.send_VT(mod_sample)
    
	elif err not in report and duration < 15: 
		print('\nResults: It could not be determined (score = {} – duration = {})'.format(r['info']['score'], duration))
		
		# Show analysis time in hh:mh:ss
		f.time_me(start)
				 
	elif err in report:
		print('\nResults: Mutation is corrupt')

		# Copy sample into failed path & tag with letter F  
		now = datetime.now()
		name_file = str(now.year)+str(now.month)+str(now.day)+str(now.hour)+str(now.minute)
		copyfile(mod_path+CSV['Perturbations']+'_m.exe', \
		fail_path+CSV['Perturbations']+'F_'+name_file+'.exe')
		
		# Update database with basic sample's info
		CSV['Manipulated_File'], CSV['Full_Analysis_Report'], CSV['Date_Reported']  \
		= fail_path+CSV['Perturbations']+'F_'+name_file+'.exe', url_sample, str(datetime.now())
		f.write_dict_CSV('db/corrupted.csv', CSV, fields) 

		# Show analysis time in hh:mh:ss
		f.time_me(start)

	return functionality, url_sample 

	
#				MALWARE ANALYSIS STAGE (REMOTE)


def malware_analysis_HA(mod_sample, json_send_HA, CSV): 
	'''
		Analyze malware using remote service Hybrid Analysis
	'''
	
	loops = 0
	start = time()
	functionality = False

    # Wait a few minutes if server did not accept further submissions
	while json_send_HA == 429:
		print('Submission quota limit has been exceeded. Retry in 5 minutes.')
		sleep(301)

    # Retrieve report from Hybrid Analisys sandbox: report URL + Hash + Job ID
	url_sample = 'https://www.reverse.it/sample/' + json_send_HA['sha256'] + '/' + json_send_HA['job_id']
	print('\nFull report: {}\n\nStatus:'.format(url_sample))   
      
    # Use loops and sleep to keep requests low and avoid API banned by HA (Limit: 5/m)
	limit = 30
	while loops < limit: 
		try:
			# Server could return 403
			if f.url_ok(url_sample) == 200 or f.url_ok(url_sample) == 403:  
				report_HA = f.get_summary_HA(json_send_HA['sha256'])
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
                
			if loops == limit-1:
				print('ARMED exited because the limit of {} minutes has been reached.\n'.format(limit))
				quit()
				
			loops += 1

		except (requests.ConnectionError, requests.Timeout, requests.ConnectTimeout) as e: 
			print('Connection issues or API requests reached:\n{}'.format(e)) 

    # Check the likelihood that malware runs based on report
	if report_HA['domains'] or report_HA['compromised_hosts']:
		functionality = True
		print('\nResults: WORKING')
		print('Malware connects to domains or contacts hosts.') 
        
        # Show analysis time in hh:mh:ss
		f.time_me(start)

        # Send to VT to check detections
		print('Sent to VirusTotal!')
		json_send_VT = f.send_VT(mod_sample)

	else:
		if report_HA['state'] != 'ERROR':
			print('\nResults: Most likely not working')
			print('Check if manipulated sample runs before scanning.')
			print('Malware does not connect to domains or contacts hosts.') 

			# Copy sample into failed path & tag with F  
			now = datetime.now()
			name_file = str(now.year)+str(now.month)+str(now.day)+str(now.hour)+str(now.minute)
			copyfile(mod_path+CSV['Perturbations']+'_m.exe', \
			fail_path+CSV['Perturbations']+'F_'+name_file+'.exe')
			
			# Update database with basic sample's info
			CSV['Manipulated_File'], CSV['Full_Analysis_Report'] \
			= fail_path+CSV['Perturbations']+'F_'+name_file+'.exe', url_sample
			f.write_dict_CSV('db/fail_database.csv', CSV, fields) 

			# Show analysis time in hh:mh:ss
			f.time_me(start)

	return functionality, url_sample    


#				MALWARE DETECTION STAGE (VIRUSTOTAL & METADEFENDER)


def malware_detection_VT(sample_report, CSV): 
	'''
		Detecting malware samples using VirusTotal (remote)
		
		Input: 
			sample_report: the number of VT detections to use as benchmark
	'''
	
	loops = 0
	limit = 20
	start = time()

    # Comparing detections of both samples 
	print('\n# Malware Detection Stage #')
	print('\nOriginal sample:')
	print('Detected by {} out of {} engines \n'.format(sample_report['positives'], 
	sample_report['total'])) #, (sample_report['positives']/sample_report['total'])*100))
	print(sample_report['permalink'])
	print('\nStatus:')

    # Use loops and sleep to keep requests lows and avoid API banned by VT (Limit: 100)
	while loops < limit: 
		try:
            # Getting report of sample submitted via VT API - Rescan: False
			report = f.get_report_VT(CSV['Mod_File_Hash'], False)

	    # Check the status of sample & report	
			if report['response_code'] == -2: 
				print('The sample is queued for analysis. Next update in 60 s')
				sleep(60)

			elif report['response_code'] == 1: 
				print('\nResults: New sample found')
				print('\nDetected by {} out of {} engines \n'.format(report['positives'], #({:.2f}%)
				report['total'])) #, (report['positives']/report['total'])*100))
                
				# Print only engines detecting new sample
				av_detect = {key:val for key, val in report['scans'].items() if val['detected'] == 1}              
				print(list(av_detect.keys()))

                # Provide link to sample detections report 
				print('\n{}'.format(report['permalink']))

                # Calculate evasion rate based on original sample detections and print summary
				print('\n## Summary ##')
				print('\nEvasion rate: {:.2f}% of previous engines'.format((1-(report['positives']/report['total'])/
				(sample_report['positives']/sample_report['total']))*100))
                #print('\nEvasion rate: {:.2f}% of engines'.format((sample_report['positives']/
                #sample_report['total']-report['positives']/report['total'])*100))

                # Show detection time in hh:mm:ss
				f.time_me(start)

                # Copy successful sample into evasion path  
				now = datetime.now()
				name_file = str(now.year)+str(now.month)+str(now.day)+str(now.hour)+str(now.minute)+str(now.second)
				copyfile(mod_path+CSV['Perturbations']+'_m.exe', \
				evasion_path+CSV['Perturbations']+'m_'+name_file+'.exe')

                # Update database with sample's info 
				CSV['Manipulated_File'], CSV['MF_Detections'], CSV['Full_Detections_Report'], \
				CSV['Date_Reported'] = evasion_path+CSV['Perturbations']+'m_'+ \
				name_file+'.exe', str(report['positives'])+'/'+str(report['total']), \
				str(report['permalink']), str(report['scan_date'])
				f.write_dict_CSV('db/database.csv', CSV, fields) 

				return report['positives']

			else: # 'response_code' == 0: 
				print("Sample is not present in VirusTotal's dataset")
				sleep(60)
			loops += 1

		except (requests.ConnectionError, requests.Timeout, requests.ConnectTimeout) as e: 
			print('Connection issues or API requests threshold reached: {}'.format(e))   
            
def malware_detection_MD(sample):
	'''
		Detecting malware samples using MetaDefender (remote)
	'''
	
	import functions as f
	from time import time, sleep 
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
		print('Time elapsed: {:.2f} s'.format(time()-start))
	except:
		print('Error handling')
        
        
#				MALWARE DETECTION STAGE (LOCAL)


def malware_detection(mutation, snapshot):
	''' 
		Detecting malware samples using local scanners.
		Use malware classifiers from industry or academia: 
		Gradient Boosting [Anderson et al. 2018]: Trained with 100k
		malicious and benign samples and achieves ROC-AUC = 0.993
		Threshold of 0.9 correponds to 1% FPR at 90% TPR
		A functionality (beta)-test has been added that overcomes the
		processing time of Cuckoo by 1/3 reducing from 45 to 15 s.
	'''
	
	start = time()
	detect = False
	vm = "Windows7-Detection"
	path_m = 'e:\\mod\\' 
		
	if not (snapshot == 'GradientBoosting' or snapshot == 'Functionality'):
		print('Engines supported: GradientBoosting')
		sys.exit() 
		
	# Pre-trained Gradient Boosting Model 
	if snapshot == 'GradientBoosting': 
		av_model = f.load_av('data/gradient_boosting.pkl')		
		bin_bytes = f.readfile(mod_path+mutation) 
		score = f.get_score_local(bin_bytes, av_model)	
		if score > 0.9: # As per paper
			print('\nMalware detected.\n') 
			return True
		else: 
			print('\nSample not detected.\n')
			return False
	
	# Start & restore the VM (headless = invisible)
	state = check_output(['VBoxManage', 'showvminfo', vm]).decode('UTF-8')
	if "powered off" in state or "saved" in state:
		call(['VBoxManage', 'snapshot', vm, 'restore', 'Windows7-'+snapshot+'-Ready'])
		call(['VBoxManage', 'startvm', vm, '--type', 'headless']) 
	elif "paused" in state: 
		call(['VBoxManage', 'controlvm', vm, 'resume', '--type', 'headless'])
		
	try:
		
		# Beta-test to check functionality (Reduces time of Cuckoo by 1/3 but needs further testing) 		
		if snapshot ==  "Functionality":
			try:						
				status = check_output(['timeout', '10', 'VBoxManage', 'guestcontrol', vm, '--username', 'user', '--password', 
				'sandbox', 'run', '--exe', path_m+mutation])
				
			except Exception as err:
				if 'returned non-zero exit status 1.' in str(err): 
					print('\nMutation corrupt!\n')
					valid = False
				else:
					print('\nMutation WORKING!\n')
					valid = True
				return valid 

	except CalledProcessError as err:
		state = err
		
	# Terminate the running process
	if snapshot != "Functionality":
		s.kill()

	# Pause the VM – Use pause only if power-off is on main() 
	#call(['VBoxManage', 'controlvm', vm, 'pause', '--type', 'headless'])
	
	# Power off the VM 
	call(['VBoxManage', 'controlvm', vm, 'poweroff']) 
	
	# Show total time in hh:mm:ss
	f.time_me(start)
	
	return detect

