#!/usr/bin/env python3
'''
Welcome to ARMED & AIMED: Automatic Random/Intelligent Malware Modifications to Evade Detection. 
AxMED were designed to understand how injecting random perturbations to Windows 
portable executable malware impact static classifiers without affecting the sample's 
functionality and thus keeping the new malware files valid. 

AIMED: https://ieeexplore.ieee.org/document/8887384 
ARMED: https://ieeexplore.ieee.org/document/8714698
'''

import os
import gp
import sys
from time import time
import functions as f
import implementation as i
import data.manipulate as m
from shutil import copyfile
from datetime import datetime 
from argparse import ArgumentParser 

def main(option, scanner):
	
	# Defining paths
	mod_path = "samples/mod/"
	evasion_path = "samples/successful/"
	detected_path = "samples/successful/detected/"

    # Argument parsing & displaying __doc__
	parser = ArgumentParser(description=__doc__)
	parser.add_argument("-p", dest="myFilenameVariable", required=True,
                        help="number of perturbations to inject", metavar="perturbations")
	parser.add_argument("-r", dest="myFilenameVariable", required=False,
                        help="number of rounds to run", metavar="rounds")
	parser.add_argument("-m", dest="myFilenameVariable", required=True,
                        help="number of manipulated files expected", metavar="mutations exp.")
	parser.add_argument("-t", dest="myFilenameVariable", required=False,
                        help="run until detections are below threshold", metavar="detection thresh.")
	args = parser.parse_args()

	# Processing input from terminal
	sample, n, rounds, files_expected, detection_threshold = i.handling_input(sys.argv)

	# Convert malware sample into binaries
	bin_bytes = f.readfile(sample) 
    
    # ARMED: Fixed length of sequence -- Using remote/local sandbox (HT/Cuckoo) + remote (VT)/local detection 
	if option == 'ARMED': 
		start_ARMED = time()
		i.armed(bin_bytes, sample, n, rounds, files_expected, detection_threshold, scanner)
		f.time_me(start_ARMED)
	
	# ARMED II: Incremental Iterations of perturbations' sequence -- Using local sandbox + local detection	
	elif option == 'ARMED2': 
		start_ARMED2 = time()
		i.armed2(bin_bytes, sample, n, rounds, files_expected, scanner)
		f.time_me(start_ARMED2)
	
	# AIMED: Fixed length & optimized order of perturbations -- GP with local sandbox + detection
	elif option == 'AIMED': 
		size_population = 4 # & n = length_sequence (number of perturbations)
		start_AIMED = time()
		i.aimed(bin_bytes, sample, size_population, n, files_expected, scanner) 
		f.time_me(start_AIMED)		
		
	# COMPARE: Examine intelligent evolutionary algorithm against random (AIMED vs ARMED) 
	elif option == 'COMPARE': 
		start_COMPARE = time()
		i.comparing(bin_bytes, sample, n, rounds, files_expected, detection_threshold, scanner)
		f.time_me(start_COMPARE)
		
		
if __name__ == '__main__':
	scanner = 'GradientBoosting'
	main('ARMED', scanner)
		
