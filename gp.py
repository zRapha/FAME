#!/usr/bin/env python3

# Genetic Programming implementation:
# Inspired on https://github.com/lowerkey/genetic_programming

# Use numpy.random instead of random.random() to leverage the Mersenne Twister implementation
# to generate pseudorandom numbers: http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/ARTICLES/mt.pdf

# Estimated processing: (generations-1)*2 + size_population * func_test(mutation) * detect(mutation)

import os
import math
import operator
import numpy as np
import config as cfg
from tqdm import tqdm
import functions as f
import implementation as i

EXPLORATION_SET = cfg.file['paths']['exploration']


class Chromosome:

	def __init__(self, code, length_sequence):
		self.cost = 0
		self.code = code
		self.length_sequence = length_sequence

	def __getitem__(self, index):
		return self.code[index]

	def __setitem__(self, index, value):
		self.code[index] = value

	def mate(self, chromosome):

		""" Perform crossover between two genes """

		middle = int(math.floor(len(self.code) / 2))
		return [Chromosome(self.code[:middle] + chromosome.code[middle:], len(self.code)),
				Chromosome(chromosome.code[:middle] + self.code[middle:], len(self.code))]

	def mutate(self, chance):

		""" Random genetic mutation on genes """

		if np.random.random() < chance:
			return
		else:
			index = int(np.random.random() * len(self.code))
			self.code[index] = int(np.random.random() * self.length_sequence)

	def random(self, length):

		""" Generate random genes """

		code = []
		for _ in range(length):
			code.append(int(np.random.random() * self.length_sequence))
		self.code = code

	def calcCost(self, detected, generation, diff, size_dir=100, conf_rate=0, search_UAP=False):

		""" Calculate the cost of each sample state: corrupt, detected, and evasive """

		# Black-box attacks
		if search_UAP and not conf_rate:

			# status == 'corrupt'
			if detected == '':
				self.cost += (10 + generation + diff) / size_dir
			# status = 'detected'
			elif detected:
				self.cost += (50 + generation + diff) / size_dir
			# status = 'evasion'
			elif not detected:
				self.cost += (1000 + generation + diff) / size_dir  # 1000 because it needs to make a difference

		# Gray-box attacks (using only confidence rate of classifier)
		elif search_UAP and conf_rate:
			self.cost += 1 - conf_rate

		# "Input-specific" black-box attack
		else:
			# status == 'corrupt'
			if detected == '':
				self.cost += 10 + generation + diff
			# status = 'detected'
			elif detected:
				self.cost += 50 + generation + diff
			# status = 'evasion'
			elif not detected:
				self.cost += 100 + generation + diff


class Population:

	def __init__(self, size, length_sequence):
		self.members = []
		self.mutations_processed = []
		self.potential_uap = []
		self.length_sequence = length_sequence
		self.new_evasions = 0
		self.corrupt_mutations = 0
		self.diff_samples = 0
		self.rounds = cfg.file.getint('aimed', 'rounds')
		self.size_population = size
		for _ in range(size):
			chromosome = Chromosome(code='', length_sequence=length_sequence)
			chromosome.random(self.length_sequence)
			self.members.append(chromosome)
		self.generationNumber = 1

	def calcCosts(self, detected, generation, diff):
		for member in self.members:
			member.calcCost(detected, generation, diff)

	def mutate(self, chance):
		for member in self.members:
			member.mutate(chance)

	def breed(self):
		middle = int(math.floor(self.size_population / 2))
		for idx in range(0, middle - 1, 2):
			children = self.members[idx].mate(self.members[idx + 1])
			children[0].mutate(0.1)
			children[1].mutate(0.1)
			self.members[middle + idx] = children[0]
			self.members[middle + idx + 1] = children[1]

	def selection(self):

		""" Select the fittest members for the next generation """

		print("\n### Generation {} ###".format(self.generationNumber))

		# Sort cost descending to group highest fitness at the beginning of the list
		self.members = sorted(self.members, key=lambda member: member.cost, reverse=True)

		# If genes are equal & there are different fit genes on the list, swap them
		for elem in range(self.size_population - 1):
			if self.members[elem].code == self.members[elem + 1].code:  # and self.members[elem].cost >= 100:
				for z in range(2, self.size_population - 1):
					if self.members[z].code != self.members[elem].code and self.members[z].code != self.members[elem+1].code:
						self.members[elem] = self.members[z]
						break

		# Show updated population
		print('\n# Population: ', end='')
		[print(self.members[s].code, round(self.members[s].cost, 4), end=' # ') for s in range(len(self.members))]
		print('\n')

	def listEvasions(self):

		""" Show evasive members """

		sequence_list = []
		[sequence_list.append(sequence) for sequence in self.mutations_processed if
		 sequence[2] > 0 and sequence[0] not in sequence_list]
		return sequence_list

	def allEvasion(self):

		""" Check whether all members are evasive """

		duplicates = []
		if self.members[0].cost < 100:
			return False
		for z in range(len(self.members) - 1):
			if self.members[z].cost == self.members[z + 1].cost:
				pass
			else:
				return False

		# Create a list with only member.code to make it hashable
		for k in self.members:
			duplicates.append(k.code)

		# Make sure there are no duplicated genes in the population
		if len(set(map(tuple, duplicates))) == len(self.members):
			print('\nAll sequences in the population lead to evasive mutations!')
			print('\nPopulation: ', end='')
			[print(self.members[z].code, self.members[z].cost, end=' # ') for z in range(len(self.members))]
			return True

	def generation(self, file, actions, search_uap=False):

		# Run until termination criteria are met
		if search_uap:
			while not self._generation_uap(actions):
				pass
		else:
			while not self._generation(file, actions):
				pass

		# Once finished, show evasive sequences if any sorted by most evasive
		if self.new_evasions:
			list_evasions = sorted(self.listEvasions(), key=operator.itemgetter(2), reverse=True)
			number_fittest_evasions = math.floor(len(list_evasions) / 10)
			print('\nAll evasive sequences found: {}\n'.format(len(list_evasions)))
			print('Displaying only 10% of fittest evasions:')
			for seq in range(number_fittest_evasions):
				print('Sequence: {} -- Fitness: {} -- Evasions: {}'.format(list_evasions[seq][0],
															   round(list_evasions[seq][1], 2), list_evasions[seq][2]))
			return list_evasions
		else:
			print('No evasive sequences found.')

		return 0

	def _generation(self, sample, actions):

		# Set UseVT to VirusTotal report
		useVT = cfg.file.getboolean('remote', 'useVT')

		# Call selection before breeding
		self.selection()

		# Breeding & mutating and adding children to the members list for Selection afterwards
		self.breed()

		gene_num = 0
		scanner = cfg.file['aimed']['model']
		for member in self.members:
			existing_member = False

			# If mutation was processed retrieve fitness value & avoid processing again
			for x in range(len(self.mutations_processed)):
				if self.mutations_processed[x][0] == member.code:
					member.cost = self.mutations_processed[x][1]
					# print('\nFitness: {}'.format(member.cost))
					existing_member = True
					break

			evasion = 0
			if not existing_member:

				# First generation calculates all genes, then breeds+mutates 2 members per generation
				gene_num += 1
				if self.generationNumber == 1:
					print('# Calculating fitness for gene {} of {}: {} #'.format(gene_num, len(self.members),
																				 member.code))
				else:
					print('# Calculating fitness for child {}: {} #'.format(gene_num, member.code))

				# Inject children sequences to input object to create four adversarial examples
				bin_bytes = f.readfile(sample)
				mod_sample = f.rec_mod_files(bin_bytes, actions, member.code, len(member.code) - 1)

				# If adversarial file returns errors, terminate in current generation
				if not mod_sample:
					return True

				# Collect info to writeCSV function
				mod_sample_hash = f.hash_files(mod_sample)
				sample_report = {'positives': 1, 'total': 1}
				CSV = f.collect_info_CSV(sample, sample_report, len(member.code), member.code,
										 mod_sample_hash, f.hash_files(sample))

				# Analyze functionality results
				if cfg.file.getboolean('aimed', 'integrityCheck'):
					funcional, url_sandbox = i.malware_analysis(mod_sample, useVT, CSV)
				else:
					# When f.batch_functionality_test() is used instead of online verification
					funcional, url_sandbox = True, "www.no_integrity_test.com"

				#  Analyze detection results
				if funcional:
					# print('Running detection for gene:', member.code)
					detected, _ = i.malware_detection(mod_sample, scanner)
					mutation_name = str(len(member.code)) + '_m.exe'
					evasion = i.save_file_database(detected, mutation_name, url_sandbox, CSV, scanner)
					self.new_evasions += evasion

					# Calculate difference between original sample and mutation
					self.diff_samples = f.get_difference(sample, mod_sample)
					diff_adjusted = round(self.diff_samples / 100000, 3)  # Constant empirically defined

					# Set cost to adversarial instances
					member.calcCost(detected, self.generationNumber, diff_adjusted)
				else:
					# Send empty when corrupt
					member.calcCost('', self.generationNumber, 0)
					self.corrupt_mutations += 1

				self.mutations_processed.append([member.code, member.cost, evasion])

				print('Sequence: {} – Fitness: {}\n'.format(member.code, member.cost))

		if self.new_evasions:
			print('# Evasive mutations found: {} #'.format(self.new_evasions))
			print('# Corrupt mutations found: {} #\n'.format(self.corrupt_mutations))

		# Termination: number of evasions achieved or number of generations reach termination defined
		files_expected = cfg.file.getint('aimed', 'advFilesExpected')
		termination_per_generation = files_expected ** 2 if files_expected >= 10 else self.rounds
		if self.generationNumber == termination_per_generation:  # self.new_evasions >= files_expected or
			return True

		self.generationNumber += 1
		return False

	def _generation_uap(self, actions):

		# Set UseVT to VirusTotal report
		useVT = cfg.file.getboolean('remote', 'useVT')

		# Call selection before breeding
		self.selection()

		# Breeding & mutating and adding children to the members list for Selection afterwards
		self.breed()

		# Calculate size of directory
		files_exp_set = os.listdir(EXPLORATION_SET)
		size_exp_set = len(files_exp_set)

		gene_num = 0
		scanner = cfg.file['aimed']['model']
		for member in self.members:
			existing_member = False

			# If mutation was processed retrieve fitness value & avoid processing again
			for x in range(len(self.mutations_processed)):
				if self.mutations_processed[x][0] == member.code:
					member.cost = self.mutations_processed[x][1]
					# print('\nFitness: {}'.format(member.cost))
					existing_member = True
					break

			if not existing_member:

				# First generation calculates all genes, then breeds+mutates 2 members per generation
				gene_num += 1
				if self.generationNumber == 1:
					print('# Calculating fitness for gene {} of {}: {} #'.format(gene_num, len(self.members),
																				 member.code))
				else:
					print('# Calculating fitness for child {}: {} #'.format(gene_num, member.code))

				# Picking sequentially each file from source folder
				current_file = 1
				evasions_in_generation = 0
				for each_sample in tqdm(sorted(os.listdir(EXPLORATION_SET))):

					# Convert selected sample into binaries
					sample = os.path.join(EXPLORATION_SET, each_sample)
					bin_bytes = f.readfile(sample)

					# Inject children sequences to input file to create four adversarial examples
					mod_sample = f.rec_mod_files(bin_bytes, actions, member.code, len(member.code) - 1)

					# If adversarial example returns errors, terminate in current generation
					if not mod_sample:
						os.rename(os.path.join(EXPLORATION_SET, each_sample), EXPLORATION_SET + 'LIEF_Error_' + each_sample)
						return True

					# Collect info to writeCSV function
					mod_sample_hash = f.hash_files(mod_sample)
					sample_report = {'positives': 1, 'total': 1}
					CSV = f.collect_info_CSV(sample, sample_report, len(member.code), member.code,
											 mod_sample_hash, f.hash_files(sample))

					# Analyze functionality results
					if cfg.file.getboolean('aimed', 'integrityCheck'):
						funcional, url_sandbox = i.malware_analysis(mod_sample, useVT, CSV)
					else:
						# When f.batch_functionality_test() is used instead of online verification
						funcional, url_sandbox = True, "www.no_integrity_test.com"

					#  Analyze detection results
					if funcional:
						# print('Running detection for gene:', member.code)
						detected, score = i.malware_detection(mod_sample, scanner, verbose=False)
						mutation_name = str(len(member.code)) + '_m.exe'
						self.new_evasions += i.save_file_database(detected, mutation_name, url_sandbox, CSV, scanner,
																  verbose=False)

						# Calculate difference between original sample and mutation
						self.diff_samples = f.get_difference(sample, mod_sample)
						diff_adjusted = round(self.diff_samples / 100000, 3)  # Constant empirically defined

						# Set cost to adversarial instances
						member.calcCost(detected, self.generationNumber, diff_adjusted, size_dir=size_exp_set,
										conf_rate=score, search_UAP=True)

						if not detected:
							evasions_in_generation += 1
					else:
						# Send empty when corrupt
						member.calcCost('', self.generationNumber, 0, size_dir=size_exp_set, search_UAP=True)
						self.corrupt_mutations += 1

					current_file += 1

				# Check if member has potential to be UAP
				if evasions_in_generation >= 20:
					self.potential_uap.append([member.code, member.cost, evasions_in_generation])

				self.mutations_processed.append([member.code, member.cost, evasions_in_generation])

				print('\nSequence: {} – Fitness: {} - Evasions: {}\n'.format(member.code, round(member.cost, 4),
																			 evasions_in_generation))

		if self.potential_uap:
			print('# Potential UAP candidates found: {} #'.format(len(self.potential_uap)))

		# Termination: number of evasions achieved or number of generations reach termination defined
		files_expected = cfg.file.getint('aimed', 'advFilesExpected')
		termination_per_generation = files_expected ** 2 if files_expected >= 10 else self.rounds
		if self.generationNumber == termination_per_generation:
			if self.potential_uap:
				print("\nUAP candidates:")
				for candidate in range(len(self.potential_uap)):
					print('Sequence: {} -- Fitness: {} -- Evasions: {}'.format(self.potential_uap[candidate][0],
																			   round(self.potential_uap[candidate][1], 2),
																			   self.potential_uap[candidate][2]))
			return True

		self.generationNumber += 1
		return False
