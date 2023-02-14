#!/usr/bin/env python3

import matplotlib
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter

matplotlib.use('Agg')


def csv_into_list(CSV, sample):
	# Setting fields for CSV
	fields = ['Original_File', 'OF_Detections', 'Manipulated_File', 'MF_Detections', 'Perturbations',
			  'Perturbations_Injected',
			  'Full_Detections_Report', 'Full_Analysis_Report', 'Mod_File_Hash', 'Original_File_Hash', 'Date_Reported']

	# Retrieve database
	df = pd.read_csv(CSV, names=fields, header=None)

	# Use only rows about %sample%
	df = df.loc[df['Original_File'] == 'samples/' + sample]
	if df.empty:
		print('No samples found with that name in the database.')
		quit()

	# Identifying x, y & cleaning out detections values. Only for success
	# samples otherwise just get perturbations as there is no detections
	if not df['MF_Detections'].isnull().any():
		# print(df['MF_Detections'])
		df['MF_Detections'] = df['MF_Detections'].map(lambda x: x[:2])
		detections = df['MF_Detections'].values.tolist()

		for i in range(len(detections)):
			if '/' in detections[i]:
				detections[i] = detections[i][:1]

		# Merging both structures into one list skipping headers
		perts_and_detections = list(map(list, zip(df['Perturbations'][0:], detections[0:])))

	else:
		perts_and_detections = list(df['Perturbations'][1:])

	# Retrieving detections ratio for original file
	benchmark = df['OF_Detections'].values[0]

	return perts_and_detections, benchmark[:2]


def accumulative_counter(perts_and_detections):
	keys = map(str, list(range(26)))[1:]
	accumulative_dict = {key: 0 for key in keys}
	counter_dict = {key: 0 for key in keys}

	val1, val2 = perts_and_detections[:2]
	if val1 != val2:  # Check whether database.csv (successes) or fail_database.csv (fails) is handed
		for i in range(len(perts_and_detections)):
			accumulative_dict[perts_and_detections[i][0]] = accumulative_dict[perts_and_detections[i][0]] + \
															int(perts_and_detections[i][1])
			counter_dict[perts_and_detections[i][0]] = counter_dict[perts_and_detections[i][0]] + 1
	else:
		c = Counter(perts_and_detections)
		c = {int(k): int(v) for k, v in c.items()}
		counter_dict = dict(sorted(c.items()))

	# Removing keys with zero values to avoid ZeroDivisionError
	accumulative_dict = {k: v for k, v in accumulative_dict.items() if v != 0}
	counter_dict = {k: v for k, v in counter_dict.items() if v != 0}

	return accumulative_dict, counter_dict, len(keys)


def string_to_int_list(perts_and_detections):
	# Converting str list into int list
	list_perts = [int(a) for a, b in perts_and_detections]
	list_detections = [int(b) for a, b in perts_and_detections]
	new_list = sorted(list(map(list, zip(list_perts, list_detections))))

	return new_list


def det_vs_pert(CSV, sample):
	# Converting CSV into list of list	
	perts_and_detections, benchmark = csv_into_list(CSV, sample)

	# Calculating accumulator and counter of detections based on perturbations injected
	accumulative_dict, counter_dict, len_keys = accumulative_counter(perts_and_detections)
	print('Number of samples per injection:\n{}'.format(counter_dict))

	# Building final dict with perturbations as key and average of detections as values & then sort
	avg_dict = {int(k): round(accumulative_dict[k] / counter_dict[k]) for k in accumulative_dict.keys() & counter_dict}
	avg_dict = dict(sorted(avg_dict.items()))

	# Defining x & y
	x = list(avg_dict.keys())
	y = list(avg_dict.values())

	# Plot ARMED's new mutations performance 
	plt.figure()
	ax = plt.gca()
	plt.plot(x[:len_keys], y[:len_keys], c='b', label='Average')  # 'Mutations')

	# Formatting 
	ax.set_xlim(2, len_keys)
	ax.set_ylim(0, 57)
	# ax.xaxis.set_major_formatter(matplotlib.ticker.StrMethodFormatter('{x:,.0f}'))
	# ax.set_title("ARMED: Average Detections of New Mutations [n={}]".format(len(perts_and_detections)))
	ax.set_xlabel('Perturbations')
	ax.set_ylabel('Average of VirusTotal Detections')
	plt.hlines(y=int(benchmark), colors='r', xmin=0, xmax=len_keys, linestyles='dashed')  # , label='Original file')
	plt.legend(loc=1)
	plt.savefig('graphics/' + sample + '/VTEvsPI.png')


def scatter_plot(CSV, sample):
	# Converting CSV into list of list	
	perts_and_detections, benchmark = csv_into_list(CSV, sample)

	# Converting str list into int list
	new_list = string_to_int_list(perts_and_detections)

	# Defining x, y and N
	x = [int(a) for a, b in new_list]
	y = [int(b) for a, b in new_list]
	area = 10

	# Plot each mutated sample in ARMED database
	ax = plt.gca()
	plt.scatter(x[:300], y[:300], s=area, c='black', alpha=0.5, label="Mutations (S')")
	plt.hlines(y=int(benchmark), colors='r', xmin=0, xmax=22, linestyles='dashed', label="Original (S)")

	# General formatting
	ax.set_xlim(1.9, 25.1)
	# ax.xaxis.set_major_formatter(matplotlib.ticker.StrMethodFormatter('{x:,.0f}'))
	ax.set_ylim(0, 57)
	# ax.set_title("ARMED: Distribution of Mutations [n={}]".format(N))
	ax.set_xlabel('Number of perturbations injected')
	ax.set_ylabel('Number of detection engines')  # (max = 68)')
	ax.legend(loc='upper center', bbox_to_anchor=(0.576, 1.01), fancybox=False, shadow=False, ncol=5)
	plt.savefig('graphics/' + sample + '/scatter_plot.png')


def ratio_functional(CSV, CSV_fail, sample):
	# Converting CSV into list of list
	perts_and_detections, benchmark = csv_into_list(CSV, sample)
	perts_fail, benchmark_fail = csv_into_list(CSV_fail, sample)

	# Counting detections of manipulated sample based on perturbations injected
	_, counter_dict, len_keys = accumulative_counter(perts_and_detections)
	_, counter_dict_fail, _ = accumulative_counter(perts_fail)
	# print('Number of samples per injection: (fail database)\n{}'.format(counter_dict_fail))

	# Defining y vars
	y = list(counter_dict.values())
	y_fail = list(counter_dict_fail.values())

	# Plot ration of functional vs. non-functional
	plt.figure()

	# Values of each bar
	bars_s = y[:len_keys]
	bars_f = y_fail[:len_keys]
	sum_y = sum(y_fail[:len_keys]) + sum(y[:len_keys])

	# Check 10 perts were injected and all p > 10
	if len(bars_s) < 10 or y[0] < 10:
		print('Not enough data for bar plot yet')
		quit()

	# Position of bars on x-axis
	r = list(range(24))

	# Names of group and bar width
	names = map(str, list(range(26)))[2:]
	barWidth = 0.85

	# Create successful & failed mutations bars
	plt.bar(r, bars_s, color='darkgray', edgecolor='white', width=barWidth, label='Functional')
	plt.bar(r, bars_f, bottom=bars_s, color='gray', edgecolor='white', width=barWidth, label='Non-functional')

	# Formatting
	# plt.title("ARMED: Functional vs. Non-functional Mutations [n={}]".format(sum_y))
	plt.hlines(y=sum_y / len(y[:len_keys]), colors='r', xmin=0, xmax=len_keys - 2, linestyles='dashed', label='Average')
	plt.ylim(0, max(y_fail) + y[0] + 5)
	plt.xticks(r, names)
	plt.xlabel("Number of perturbations injected")
	plt.ylabel("Number of mutations generated")
	plt.legend(loc=2)
	plt.savefig('graphics/' + sample + '/ratio_functional.png')


if __name__ == '__main__':
	det_vs_pert('db/database.csv', 'original/keylogger')
	scatter_plot('db/database.csv', 'original/keylogger')
	ratio_functional('db/database.csv', 'db/fail_database.csv', 'original/keylogger')
