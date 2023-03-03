# FAME

![Workflow](https://github.com/zrapha/fame/actions/workflows/main.yml/badge.svg)
[![codecov](https://codecov.io/gh/zRapha/famework/branch/master/graph/badge.svg?token=oMFazw4iLl)](https://codecov.io/gh/zRapha/famework)
[![License: MPL v2](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://www.mozilla.org/en-US/MPL/2.0/)


<!--
[![PyPI version](https://badge.fury.io/py/ttkwidgets.svg)](https://badge.fury.io/py/ttkwidgets)
-->

## Welcome to the Framework for Adversarial Malware Evaluation 

FAME has been designed to evaluate ML-based malware classifiers against adversarial examples. It aims to provide understanding on how byte-level transformations can be injected into Windows Portable Executable (PE) files and compromise models. Moreover, it supports integrity verification to ensure that the adversarial examples remain valid after manipulation. This work implements the action space proposed on the [OpenAI gym malware](https://github.com/endgameinc/gym-malware) environment. It has been implemented and tested using Fedora 30 and Ubuntu 16 with Python3. Library versions are defined in the `requirements.txt` file.

The framework consists of the following modules: ARMED, AIMED / AIMED-RL & GAME-UP. 

### GAME-UP: Generating Adversarial Malware Examples with Universal Perturbations

This module intends to analyze how Universal Adversarial Perturbations (UAPs) can be useful to create efficient adversarial examples compared to input-specific attacks. It explores how real malware examples in the problem-space affect the feature-space of classifiers to identify systematic weaknesses. Also, it implements a variant of adversarial training to improve the resilience of static ML-based malware classifiers for Windows PE binaries.

### AIMED: Automatic Intelligent Modifications to Evade Detection

This approach focus on understanding how sensitive static malware classifiers are to adversarial examples. It uses different techniques including Genetic Programming (GP) and Reinforcement Learning (RL) to inject perturbations to Windows PE malware without compromising its functionality, keeping the frehsly generated adversarial example valid.

### ARMED: Automatic Random Modifications to Evade Detection

With this option sequences of transformations are chosen randomly to identify weakspots in the classifier. This module implements a pipeline that is able to automatically generate realizable adversarial examples in the malware context. 

## How to run FAME 

Here we describe how to run `FAME` by installing directly the package from `pip`. For more detail about running from source and manual configuration of parameters refer to the [install](https://github.com/zRapha/FAME/blob/master/INSTALL.md) instructions. 

Install `FAME`:
```
$ pip install famework
```
Run `FAME` with any module (e.g., AIMED):
```
$ fame aimed
```

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
@article{labaca-castro2022universal,
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
