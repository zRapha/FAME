.. FAMEwork documentation master file, created by
   sphinx-quickstart on Thu Oct  7 14:19:09 2021.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

====================================
Welcome to FAME's documentation!
====================================

FAME was designed to understand how byte-level transformations could automatically be injected to Windows Portable Executable (PE) files and compromise ML-based malware classifiers. Moreover, it supports integrity verification to ensure that the new adversarial examples are valid. This work implements the action space proposed on the [OpenAI gym malware](https://github.com/endgameinc/gym-malware) environment. It has been implemented in Fedora 30 and tested on Ubuntu 16 using Python3. Library versions are defined in requirements.txt file.

The framework consists of four modules, namely, ARMED, AIMED, AIMED-RL & GAME-UP

GAME-UP: Generating Adversarial Malware Examples with Universal Perturbations

This work intends to understand how Universal Adversarial Perturbations (UAPs) can be useful to create efficient adversarial examples compared to input-specific attacks. Furthermore, it explores how real malware examples in the problem-space affect the feature-space of classifiers to identify systematic weaknesses. Also, it implements a variant of adversarial training to improve the resilience of static ML-based malware classifiers for Windows PE binaries.

AIMED-RL: Automatic Intelligent Modifications to Evade Detection (with Reinforcement Learning)

This work is focused on understanding how sensitive static malware classifiers are to adversarial examples. It uses different techniques including Genetic Programming (GP) and Reinforcement Learning (RL) to inject perturbations to Windows portable executable malware without compromising its functionality and, thus, keeping the new generated adversarial example valid.

.. toctree::
   :maxdepth: 2
   :caption: Contents:



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
