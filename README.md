# FAME

![Workflow](https://github.com/zrapha/famework/actions/workflows/main.yml/badge.svg)
[![codecov](https://codecov.io/gh/zRapha/famework/branch/master/graph/badge.svg?token=oMFazw4iLl)](https://codecov.io/gh/zRapha/famework)
[![License: MPL v2](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://www.mozilla.org/en-US/MPL/2.0/)
[![Documentation Status](https://readthedocs.com/projects/famework-famework/badge/?version=latest&token=49ee59c4023ff442c8f2ecf706a700f8b262bc03c8fcefb29cb7effc52584998)](https://famework-famework.readthedocs-hosted.com/en/latest/?badge=latest)

<!--
[![PyPI version](https://badge.fury.io/py/ttkwidgets.svg)](https://badge.fury.io/py/ttkwidgets)
-->

## Welcome to the Framework for Adversarial Malware Evaluation 

FAME has been designed to evaluate ML-based malware classifiers against adversarial examples. It aims to provide understanding on how byte-level transformations can be injected into Windows Portable Executable (PE) files and compromise models. Moreover, it supports integrity verification to ensure that the adversarial examples remain valid after manipulation. This work implements the action space proposed on the [OpenAI gym malware](https://github.com/endgameinc/gym-malware) environment. It has been implemented and tested using Fedora 30 and Ubuntu 16 with Python3. Library versions are defined in the requirements.txt file.

> FAME: Framework for Adversarial Malware Evaluation, Labaca-Castro et al., 2022

The framework consists of four modules, namely, ARMED, AIMED, AIMED-RL & GAME-UP, which are described below:

### GAME-UP: Generating Adversarial Malware Examples with Universal Perturbations

This work intends to understand how Universal Adversarial Perturbations (UAPs) can be useful to create efficient adversarial examples compared to input-specific attacks. Furthermore, it explores how real malware examples in the problem-space affect the feature-space of classifiers to identify systematic weaknesses. Also, it implements a variant of adversarial training to improve the resilience of static ML-based malware classifiers for Windows PE binaries.

> Realizable Universal Adversarial Perturbations, Labaca-Castro et. al., 2022

### AIMED: Automatic Intelligent Modifications to Evade Detection

This work is focused on understanding how sensitive static malware classifiers are to adversarial examples. It uses different techniques including Genetic Programming (GP) and Reinforcement Learning (RL) to inject perturbations to Windows portable executable malware without compromising its functionality and, thus, keeping the new generated adversarial example valid.

> AIMED-RL: Exploring Adversarial Malware Examples with Reinforcement Learning., Labaca-Castro et al., ECML PKDD 2021  
> AIMED: Evolving Malware with Genetic Programming to Evade Detection, Labaca-Castro et al., IEEE TRUSTCOM 2019  
> ARMED: Automatic Random Malware Modifications to Evade Detection, Labaca-Castro et al., IEEE ICIM 2018  

## Installation instructions

Clone the FAME repository:
```
$ git clone https://github.com/zRapha/FAME
```
Create a virtual environment & activate it:
```
$ python3.7 -m venv fame-env
$ source fame-env/bin/activate
```
Update pip if needed (pip~=20.0):
```
$ pip install --upgrade pip
```

Install required packages:
```
$ pip install -r requirements.txt
```
## Integrity test verification  
Per default the functionality stage is implemented using Cuckoo, an analysis environment that has an extensive documentation support: https://cuckoo.sh/docs/. Cuckoo provides dynamic analysis results, which can be useful to understand the adversarial examples generated. A local beta-test implementation is also provided for further extension.

## Malware classification   
Local classification models are implemented to perform detection using  pre-trained malware classifier, namely, LightGBM trained with both EMBER and SOREL datasets. For those interested in more classifiers, we provide the option of using aggregators via REST APIs in order to assess adversarial examples against a wider range of commercial engines.

## Dataset
There are several public repositories containing labeled malicious files to test the environment. Once the data is acquired, it should be placed under samples/malware_set/.

## Further environment isolation [optional]
Even though the manipulations do not require to run any file, the integrity verification stage does. Hence, it is  recommended to use isolated sandboxes and simulated services. One option is to use _inetsim_.

Disable interface:
```
$ sudo ifconfig <network_int> down
```

Run inetsim:
```
$ cd /etc/default/inetsim-1.2.8/
$ sudo ./inetsim
```

Note that automatically retrieving the detection rate for a malware file from an online aggregator will no longer be functional unless adjusted manually.

## How to run FAME

### 1. Activate Cuckoo Python venv:
```
$ source ~/Documents/venvs/cuckoo-env/bin/activate
```

> If integrity verification is implemented proceed with _2_, otherwise jump to _5_. 

### 2. Run Mongo DB for webserver:
```
$ sudo service mongod start
```

### 3. Run webserver [optional]:
```
$ cd ~/.cuckoo/
$ cuckoo web
``` 

### 4. Run API & Cuckoo sandbox:
```
$ cuckoo api
$ cuckoo
```

### 5. Adjust configuration and initial parameters:
```
$ vi config.ini
```

### 6. Run FAME with the desired module (e.g., AIMED):
```
$ ./main.py aimed
```

## Segmentation fault 
We have observed that injecting some combinations of perturbations to specific PE files raise segmentation fault 
issues. Due to the nature of memory violations and the occurrence of this issue (in our experiments less than 0.02% of 
the cases) we recommend either adjusting the transformations' sequence to a different combination or trying a new example. 
Sometimes not patching the original import table, setting builder.patch_imports(False), may also help prevent this issue. 
A workaround is curating the dataset by identifying the PE file and excluding it from the process.

## Contributors 
We appreciate the contributions that have been helping improve this work. Below we list authors and modules they
contributed to: 

| Contributor     | University                     | Module                 |
|-----------------|--------------------------------|------------------------|
| Sebastian Franz | Technische Universität München | Reinforcement Learning |

## Citation  

If you find this work useful you are highly encouraged to cite the following articles. For the framework, you can refer to:

`FAME`
```
@article{labaca-castro2022fame,
  title={Framework for Adversarial Malware Evaluation},
  author={Labaca-Castro, Raphael and Rodosek, Gabi Dreo},
  journal={TBD},
  year={2022}
}
```
---
If you worked with more specific modules feel free to reference them separately:

`GAME-UP`
```
@article{labaca-castro2021universal,
  title={Realizable Universal Adversarial Perturbations for Malware},
  author={Labaca-Castro, Raphael and Mu{\~n}oz-Gonz{\'a}lez, Luis and Pendlebury, Feargus and Rodosek, Gabi Dreo and Pierazzi, Fabio and Cavallaro, Lorenzo},
  journal={arXiv preprint arXiv:2102.06747},
  year={2022}
}
```

`AIMED-RL`
```
@inproceedings{labaca-castro2021aimed-rl,
  title={AIMED-RL: Exploring Adversarial Malware Examples with Reinforcement Learning },
  author={Labaca-Castro, Raphael and Franz, Sebastian and Rodosek, Gabi Dreo},
  booktitle={Joint European Conference on Machine Learning and Knowledge Discovery in Databases (ECML PKDD)},
  pages={37--52},
  year={2021},
  organization={Springer}
}
```

`AIMED`
```
@inproceedings{labaca-castro2019aimed,
  title={AIMED: Evolving Malware with Genetic Programming to Evade Detection},
  author={Labaca-Castro, Raphael and Schmitt, Corinna and Rodosek, Gabi Dreo},
  booktitle={2019 18th IEEE International Conference On Trust, Security And Privacy In Computing And Communications/13th IEEE International Conference On Big Data Science And Engineering (TrustCom/BigDataSE)},
  pages={240--247},
  year={2019},
  organization={IEEE}
}
```

`ARMED`
```
@inproceedings{labaca-castro2019armed,
  title={ARMED: How Automatic Malware Modifications Can Evade Static Detection?},
  author={Labaca-Castro, Raphael and Schmitt, Corinna and Rodosek, Gabi Dreo},
  booktitle={2019 5th International Conference on Information Management (ICIM)},
  pages={20--27},
  year={2019},
  organization={IEEE}
}
```
