# ARMED & AIMED 
***************

Welcome to ARMED & AIMED (AxMED): Automatic Random/Intelligent Malware Modifications to Evade Detection 

AxMED was designed to understand how automatically injected perturbations to Windows portable executable (PE) malware impact static classifiers without affecting the sample's functionality and thus keeping the new malicious mutations valid. This work implements the action space and GBDT model proposed on the [OpenAI gym malware](https://github.com/endgameinc/gym-malware) environment.

SETUP
=====

## Part 1: Installation instructions for AxMED ##

Download the ARMED/AIMED repository: 
```
$ git clone https://github.com/zRapha/ARMED 
```
Create a virtual environment & activate it: 
```
$ python3 -m venv axmed-env
$ source axmed-env/bin/activate
```
Install required packages: 
```
$ pip install -r requirements.txt 
```
## Part 2: Setup a Cukcoo environment for the functionality test or use beta-test implementation ## 
The Cuckoo analysis environment has an extensive documentation support: https://cuckoo.sh/docs/. An interesting fact to use Cuckoo is that it provides dynamic analysis results, which can be useful to understand the adversarial examples generated. A local beta-test implementation is also provided to avoid using an external service. 

## Part 3: Choose detection environment ## 
By default, we implement a local classification model to perform detection using a pre-trained classifier. For those looking for more results, we provide the option of using agreggators via REST APIs in order to assess adversarial examples against a wider range of scanners. 

## Part 4: Dataset acquiring ## 
There are several public repositories containing labeled malicious samples to test your environment. Once the data is acquired, it should be placed under samples/unzipped/. 

## Optional: Further isolating the environment ##
Even though the manipulation does not require to run any file, the functionality does. Hence, we recommend using isolated sandboxes and/or reroute the traffic. One option is to use inetsim. 

- Disable interface to internet: $ sudo ifconfig <network_int> down (ping should not work)
- Run inetsim:  $ cd /etc/default/inetsim-1.2.8/ and $ sudo ./inetsim (ping should 'work' now)

Note that retrieving the detection rate for a malware sample from an online platform (e.g. VirusTotal) will no longer be functional. Therefore, manual checking for the detection rate is required. 

## Part 5: How to run AxMED ##

1. Activate Cuckoo Python venv: 
```
$ source ~/Dokumente/virtualenvironments/cuckoo-env/bin/activate
```

2. Run Mongo DB for webserver: 
```
$ sudo service mongod start 
```

3. Run webserver [optional]: 
```
$ cd ~/.cuckoo/ 
$ cuckoo web 
```

4. Run API & Cuckoo sandbox: 
```
$ cuckoo api 
$ cuckoo
```
5. Run AxMED: 
```
$ ./axmed.py -s samples/keylogger -p 5
```

CITATION
======== 

For AIMED: 
```
@inproceedings{labaca-castro2019aimed,
  title={AIMED: Evolving Malware with Genetic Programming to Evade Detection},
  author={Labaca Castro, Raphael and Schmitt, Corinna and Rodosek, Gabi Dreo},
  booktitle={2019 18th IEEE International Conference on Trust, Security and Privacy in Computing and Communications (TrustCom)},
  year={2019},
  organization={IEEE}
}
```

For ARMED: 
```
@inproceedings{labaca-castro2019armed,
  title={ARMED: How Automatic Malware Modifications Can Evade Static Detection?},
  author={Labaca Castro, Raphael and Schmitt, Corinna and Rodosek, Gabi Dreo},
  booktitle={2019 5th International Conference on Information Management (ICIM)},
  pages={20--27},
  year={2019},
  organization={IEEE}
}
```

