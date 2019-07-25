#!/usr/bin/env python3

# Genetic Programming implementation:
# Inspired on https://github.com/lowerkey/genetic_programming

# Use numpy.random instead or random.random() to leverage the Mersenne Twister implementation 
# to generate pseudorandom numbers: http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/ARTICLES/mt.pdf

# Estimated processing: (generations-1)*2 + size_population * func_test(mutation) * detect(mutation)

import numpy.random as nr
from math import floor
import functions as f
import implementation as i

class Chromosome:

    def __init__(self, code):
        self.code = code  
        self.cost = 0 	  
        
    def __getitem__(self, index): 
        return self.code[index]
		
    def __setitem__(self, index, value): 
        self.code[index] = value
 

    def mate(self, chromosome):
		
        ''' Perform crossover between two genes '''
		
        middle = int(floor(len(self.code)/2))
        return [Chromosome(self.code[:middle] + chromosome.code[middle:]),
                Chromosome(chromosome.code[:middle] + self.code[middle:])]

    def mutate(self, chance):
		
        ''' Random genetic mutation on genes '''
		
        if nr.random() < chance:
            return
        else:
            index = int(nr.random() * len(self.code))
            self.code[index] = int(nr.random() * 9)  # 9 perturbations in vector

    def random(self, length):
		
        ''' Generate random genes '''
		
        code = []
        for i in range(length):
            code.append(int(nr.random() * 9)) 
        self.code = code

    def calcCost(self, detected, generation, diff): 
		
        ''' Calculate the cost of each sample state: corrupt, detected, and evasive '''
		
		#status == 'corrupt'
        if detected == '':
            self.cost = 10 + generation + diff       
        #status = 'detected'
        elif detected == True:           
            self.cost = 50 + generation + diff 
        #status = 'evasion'
        elif detected == False:           
            self.cost = 100 + generation + diff


class Population:

    def __init__(self, size, length_sequence, show_sequences):
        self.members = []
        self.mutations_processed = []
        self.length_sequence = length_sequence
        self.new_evasions = 0
        self.corrupt_mutations = 0
        self.diff_samples = 0
        for i in range(size):
            chromosome = Chromosome('')
            chromosome.random(self.length_sequence)  
            self.members.append(chromosome)
        self.generationNumber = 1
        
        # Show the sequences & fitness of the fittest members
        self.show_sequences = show_sequences
                    
    def calcCosts(self, detected, generation, diff):
        for member in self.members:
            member.calcCost(detected, generation, diff) 

    def mutate(self, chance):
        for member in self.members:
            member.mutate(chance)

    def selection(self):
		
        ''' Select the fittest members for the next generation '''

        print("\n### Generation {} ###".format(self.generationNumber))

		# Sort cost descending to group highest fitness at the beginning of the list 
        self.members = sorted(self.members, key=lambda member: member.cost, reverse=True)
		
        # If both parents are evasive & there are other genes evasive on the list, swap one of them
        if self.members[0].code	== self.members[1].code and self.members[0].cost >= 100:   
            for z in range(2, len(self.members)-1): 
                if self.members[z].cost >= 100 and self.members[z].code != self.members[0].code and self.members[z].code != self.members[1].code:
                    self.members[0] = self.members[z]
                    break			
                    
        # Show updated population (Generations use size_population-2 because of breeding. Eg. size = 6 - 2 'children' = 4 -> 1st generation only shows 4 genes in Population)
        print('\n# Population: ', end='')
        if self.generationNumber == 1:  
            [print(self.members[z].code, self.members[z].cost, end=' # ') for z in range(len(self.members)-2)]
        else:
            [print(self.members[z].code, self.members[z].cost, end=' # ') for z in range(len(self.members))]
        print('\n')
        
    def listEvasions(self, print_results): 
		
        ''' Show evasive members '''
		
        if print_results == True: 
            return [print(sequence) for sequence in self.mutations_processed if sequence[1]>=100]
        else: 
            sequence_list = []
            [sequence_list.append(sequence) for sequence in self.mutations_processed if sequence[1]>=100]			
            return sequence_list		
   
    def allEvasion(self):  
		
        ''' Check whether all members are evasive '''
		
        duplicates = []
        if self.members[0].cost	< 100:
            return False
        for z in range(len(self.members)-1): 
            if self.members[z].cost == self.members[z+1].cost:
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

    def generation(self, mutation): 
		
		# Run until termination criteria are met
        while not self._generation(mutation):
            pass

        # Once finished, show evasive sequences if show_sequences=True 
        if self.show_sequences: 
            if self.new_evasions:
                print('\n### All evasive sequences found: ###\n')
                self.listEvasions(print_results=True)
            else: 
                print('\n### No evasive sequences found ###')
            return self.new_evasions, self.corrupt_mutations 
        else:
            return self.generationNumber
        
    def _generation(self, mutation):
                
        # Call selection before breeding
        self.selection()

        # Breeding & mutating and adding children to the members list for Selection afterwards
        children = self.members[0].mate(self.members[1])
        children[0].mutate(0.1)
        children[1].mutate(0.1)        
        self.members[-2] = children[0]
        self.members[-1] = children[1]	        
        gene_num = 0
        for member in self.members:   			
            existing_member = False
            
            # If mutation was processed retrieve fitness value & avoid processing again
            for x in range(len(self.mutations_processed)):
                if self.mutations_processed[x][0] == member.code:
                    member.cost = self.mutations_processed[x][1]
                    #print('\nFitness: {}'.format(member.cost))
                    existing_member = True   
                    break
                    
            if not existing_member:		
			
				# First generation calculates all genes, then breeds+mutates 2 members per generation
                gene_num += 1	
                if self.generationNumber == 1: 
                    print('# Calculating fitness for gene {} of {}: {} #'.format(gene_num, len(self.members), member.code))					
                else: 
                    print('# Calculating fitness for child {}: {} #\n'.format(gene_num, member.code))

    			# Inject children sequences to S to create four S'
                mod_sample = f.rec_mod_files(mutation['Malware_Bytes'], mutation['Actions'], member.code, len(member.code)-1, len(member.code))
			
	    		# Call functionality test
                json_send = f.send_local_sandbox(mod_sample) 
                
                # Get VT detections for original sample to save in db
                sample_report = f.get_report_VT(mutation['hash_sample'], rescan=False)
                #sample_report = {'positives': 49, 'total': 66} # Debug mode (without VT/offline)
                
                # Collect info to writeCSV function 
                mod_sample_hash = f.hash_files(mod_sample)                
                CSV = f.collect_info_CSV(mutation['Malware_Sample'], sample_report, len(member.code)-1, member.code, mod_sample_hash, mutation['hash_sample'])
			
		    	# Analyze functionality results (Set UseVT to VirusTotal report)	
                useVT=False
                CSV['Perturbations'] = str(len(member.code))
                funcional, url_sandbox = i.malware_analysis(mod_sample, json_send, useVT, CSV) 
                mutation_file = CSV['Perturbations']+'_m.exe'
			
		    	#  Analyze detection results
                if funcional: 
                    print('Running detection for gene:', member.code)
                    detected = i.malware_detection(mutation_file, mutation['Scanner'])
                    self.new_evasions += i.save_file_database(detected, mutation_file, url_sandbox, CSV, mutation['Scanner'])		                        
                    
                    # Calculate difference between original sample and mutation
                    self.diff_samples = f.get_difference(mutation['Malware_Sample'], mutation_file)
                    diff_adjusted = round(self.diff_samples/100000, 3) # Constant empirically defined as test
                    
                    # Set cost to S' instances
                    member.calcCost(detected, self.generationNumber, diff_adjusted) 
                else:
		    		# Send empty when corrupt 
                    member.calcCost('', self.generationNumber, 0)
                    self.corrupt_mutations += 1
            
                self.mutations_processed.append((member.code, member.cost))

                print('Sequence: {} – Fitness: {}\n'.format(member.code, member.cost))
          
        # Termination: number of evasions achieved or number of generations reach termination defined 
        termination_per_generation = mutation['Files_Expected']**2 if mutation['Files_Expected']  > 9 else 5
        if self.new_evasions >= mutation['Files_Expected'] or self.generationNumber == termination_per_generation: 
            return True         
            
        print('# Evasive mutations found: {} #'.format(self.new_evasions))
        print('# Corrupt mutations found: {} #\n'.format(self.corrupt_mutations))
                                       
        self.generationNumber += 1
        return False

