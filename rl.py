#!/usr/bin/env python3

# AIMED-RL: Automatic Intelligent Malware modifications to Evade Detection - with Reinforcement Learning
import numpy as np
import random
import distutils
from enum import Enum
import csv

import chainer
import chainerrl
import chainer.links as L
import chainer.functions as F
from chainerrl.initializers import LeCunNormal
from chainerrl.distribution import SoftmaxDistribution
from chainerrl.action_value import DiscreteActionValue
from chainerrl.optimizers import rmsprop_async
from chainerrl import links
from chainerrl.replay_buffers import EpisodicReplayBuffer

import gym
from gym import spaces

import functions as f
from collections import OrderedDict
import data.pefeatures as pefeatures
import os
from datetime import datetime
import data.manipulate as m
from time import time

ACTIONS = f.actions_vector(m.ACTION_TABLE.keys())

# Reward Weight Distributions:
STANDARD_WEIGHTS = [0.33, 0.33, 0.33]
INCREMENT_WEIGHTS = [0.5, 0.2, 0.3]  # decrease importance of similarity


# Class based on OpenAI Gym Environment and Gym Malware (https://github.com/endgameinc/gym-malware/)
class MalwareEnv(gym.Env):
    metadata = {'render.modes': ['human']}

    def __init__(self, malware_list, detection_function, analysis_function):
        random.seed(PARAM_DICT["seed"])
        self.malware_list = malware_list
        self.used_malware = []
        self.actions = ACTIONS
        self.action_space = spaces.Discrete(len(ACTIONS))
        self.actions_taken = []

        self.max_turns = PARAM_DICT["max_turns"]

        self.strategy_reset = PARAM_DICT["strategy_reset"]  # Reset actions after half
        self.strategy_inject = PARAM_DICT["strategy_inject"]  # Inject actions randomly after half
        assert not (self.strategy_reset and self.strategy_inject)  # Only one strategy possible at a time

        self.turns = 0

        # Reward weights:
        self.reward_weights = PARAM_DICT["weights"]
        assert np.sum(self.reward_weights) <= 1.0  # Sum of weights must not be bigger than 1
        self.detected_weight = self.reward_weights[0]
        self.similarity_weight = self.reward_weights[1]
        self.distance_weight = self.reward_weights[2]

        self.reward_punishment = PARAM_DICT["reward_punishment"]

        self.history = OrderedDict()

        # Functions:
        self.detector_function = detection_function
        self.functionality_function = lambda: (random.randint(0, 10), 0)  # analysis_function
        self.similarity_function = f.get_difference

        # Malware Features:
        self.feature_extractor = pefeatures.PEFeatureExtractor()
        self.current_malware = None
        self.current_manipulation = None
        self.original_bytez = None
        self.feature_space = None

    def step(self, action_index):
        # Apply strategy - Reset actions after half:
        if self.strategy_reset and self.turns == self.max_turns / 2:
            self.actions_taken = []
            self.current_manipulation = self.current_malware
            self.history[self.current_malware].append("RESET")

        self.turns += 1

        # Manipulate Malware:
        try:
            bytez = self._take_action(action_index)
            # Update State
            self.feature_space = self.feature_extractor.feature_vector(bytez)
        except Exception as e:  # PE Manipulation Errors
            print('Exception raised:', e)
            reward = 0
            episode_over = True
            return np.asarray(self.feature_space), reward, episode_over, \
                   {"detected": False, "detected_confidence": 0, "errored": True}

        reward, detected, detected_confidence = self._calculate_reward()

        max_turns_reached = False
        if self.turns >= self.max_turns:
            # reward = 0.0 Temporarily removed for last training
            max_turns_reached = True

        # print("Detected: ", detected)
        # print("Max_turns_reached:", max_turns_reached)

        episode_over = max_turns_reached or not detected
        # print("Episode over: ", episode_over)

        # Info may not be used by RL_Agent
        info = {"detected": detected, "detected_confidence": detected_confidence, "errored": False}
        return np.asarray(self.feature_space), reward, episode_over, info

    def get_random_action(self):
        action = random.randrange(0, len(self.actions))
        print("Random action: " + self.actions[action])
        return action

    def _take_action(self, action_index):
        action = self.actions[action_index]
        if self.strategy_inject and self.turns > self.max_turns / 2:
            random_index = random.randrange(start=0, stop=len(self.actions_taken) - 1, step=1)
            self.actions_taken[random_index] = action_index
            self.history[self.current_malware][random_index] = action
        else:
            self.actions_taken.append(action_index)
            self.history[self.current_malware].append(action)

        # Check to avoid 'list out of index' exceptions
        if self.turns <= self.max_turns / 2:
            self.current_manipulation = f.rec_mod_files(input_bytes=self.original_bytez,
                                                        actions=self.actions,
                                                        chosen_actions=self.actions_taken,
                                                        inject_perturbation=self.turns-1)
        return f.readfile(self.current_manipulation)

    def reset(self):
        self.turns = 0
        self.actions_taken = []
        self.current_malware = self._choose_next_malware()
        self.used_malware.append(self.current_malware)
        self.current_manipulation = self.current_malware  # For similarity
        self.original_bytez = f.readfile(self.current_malware)
        self.feature_space = self.feature_extractor.feature_vector(self.original_bytez)  # Observation space
        self.history[self.current_malware] = []

        return np.asarray(self.feature_space)

    def reset_completely(self):
        # Also reset used malware
        self.history = OrderedDict()
        self.reset()
        self.used_malware = []

    # Randomly choose next malware, which has not been used
    # If all available malware samples have already been used, list is resetting
    def _choose_next_malware(self):
        temp_list = [malware for malware in self.malware_list if self.used_malware.count(malware) == 0]
        if len(temp_list) == 0:
            temp_list = self.malware_list
            self.used_malware = []
        return random.choice(temp_list)

    # Reward = Detection (0/1) + Similarity (functions.get_difference) + Distance (self.turns)
    def _calculate_reward(self):
        max_reward = PARAM_DICT["maximum_reward"]  # AIMED-RL Paper: R_max = 10

        # ** Detected: Is the malware detected by the model? **
        # Not detected: good, detected: bad
        # Value: 0/10
        detected, confidence = self.detector_function(self.current_manipulation)
        # print("DETECTED FROM MODEL: ", detected, confidence)
        detected_reward = 0
        if not detected:
            detected_reward = max_reward

        # ** Similarity: How much does the manipulation differ from the original file? **
        # Difference ~40%: Best (empirical estimate)
        # Value: 0-10

        # Gets back the difference between original and manipulated bytez, smaller value: more similar
        difference = self.similarity_function(self.current_manipulation, self.current_malware)
        original_length = len(self.original_bytez)
        similarity_reward = self._calculate_similiarity_reward(difference, original_length)

        # ** Distance: How many actions have been taken? **
        # More turns mean more actions mean a more diverse action vector
        # Limit of 5 perturbations => Should be used completely
        # Value: #actions * (max_reward/max_perturbations)
        max_perturbations = PARAM_DICT["max_turns"] / 2 if PARAM_DICT["strategy_reset"] or PARAM_DICT["strategy_inject"] \
            else PARAM_DICT["max_turns"]  # Applying a strategy halves the amount of possible perturbations
        factor = max_reward / max_perturbations  # 2 in AIMED-RL Paper
        distance_reward = len(self.actions_taken) * factor

        # Max value: max_reward
        reward = detected_reward * self.detected_weight + similarity_reward * self.similarity_weight \
                 + distance_reward * self.distance_weight

        if self.reward_punishment:
            punishment = self._calculate_doubled_perturbation_punishment()

            if detected:  # Do not apply punishment if last perturbation lead to adversarial sample
                reward *= punishment

        return reward, detected, confidence

    # Calculate difference between best similarity (40%) and actual value and calculate reward accordingly
    def _calculate_similiarity_reward(self, difference, original):
        percent_sim = difference / original
        percent_best = 0.4  # Empirical estimate: 40% difference between original file could be best for adversarial file
        reward_sim = (1 - abs(percent_sim - percent_best)) * PARAM_DICT["maximum_reward"]  # AIMED_RL Paper: R_max = 10
        return max(0, reward_sim)  # No negative reward

    # Give punishment to doubled perturbations in actions_taken
    def _calculate_doubled_perturbation_punishment(self):
        no_punishment = 1  # no reduction
        punishment_doubled_once = 0.8  # 20% less reward
        punishment_doubled_twice = 0.6  # 40% less reward
        for action in self.actions_taken:
            if self.actions_taken.count(action) > 2:
                return punishment_doubled_twice
            if self.actions_taken.count(action) > 1:
                return punishment_doubled_once

        return no_punishment

    def render(self, mode='human', close=False):
        if self.current_malware is not None and self.history[self.current_malware] is not None:
            # print("Input object: " + str(self.current_malware))
            if "RESET" in self.history[self.current_malware]:
                index_reset = self.history[self.current_malware].index("RESET")
                history_length = len(self.history[self.current_malware])
                # print("Actions (before reset): " + str(self.history[self.current_malware][0:index_reset]))
                print("Actions (after reset): " + str(
                    self.history[self.current_malware][index_reset + 1:history_length]))
            else:
                print("Actions: " + str(self.history[self.current_malware]))
        else:
            print("Environment has not been reset.")


# The DQNSettings Enum summarizes the possible enhancements to the DQN Algorithm
class DQNSettings(Enum):
    REPLAY_BUFFER = 1
    PRIORITIZED_REPLAY_BUFFER = 2
    ADAM_OPTIMIZER = 3
    LINEAR_DECAY_EPSILON_GREEDY = 4
    BOLTZMANN_EXPLORATION = 5
    NOISY_NETS = 6
    ALGO_DQN = 7
    ALGO_ACER = 8
    ALGO_DISTDQN = 9


# Reinforcement learning agent using chainer-rl library
class RlAgent:
    def __init__(self, environment: MalwareEnv):
        self.env = environment
        self.obs_size = len(environment.feature_space)
        self.n_actions = environment.action_space.n

        if DQNSettings.ALGO_ACER.name in PARAM_DICT["agent"]:
            self.agent = self.create_acer_agent()
        else:
            self.agent = self.create_dqn_agent()

    # For Algorithm Implementation see: https://github.com/endgameinc/gym-malware/blob/master/train_agent_chainer.py
    # Rainbow: https://github.com/chainer/chainerrl/tree/master/examples/atari/reproduction/rainbow
    def create_dqn_agent(self):
        q_func = None
        if DQNSettings.ALGO_DQN.name in PARAM_DICT["agent"]:
            q_func = QFunction(self.obs_size, self.n_actions)
        elif DQNSettings.ALGO_DISTDQN.name in PARAM_DICT["agent"]:
            q_func = chainerrl.q_functions.DistributionalFCStateQFunctionWithDiscreteAction(
                ndim_obs=self.obs_size,
                n_actions=self.n_actions,
                n_atoms=51,  # See paper
                v_min=-10,  # See paper
                v_max=10,  # max reward
                n_hidden_layers=2,
                n_hidden_channels=64
            )
        assert q_func is not None

        optimizer = None
        if DQNSettings.ADAM_OPTIMIZER.name in PARAM_DICT["optimizer"]:
            optimizer = chainer.optimizers.Adam(eps=PARAM_DICT["adam_epsilon"])
            optimizer.setup(q_func)
        assert optimizer is not None

        explorer = None
        if DQNSettings.LINEAR_DECAY_EPSILON_GREEDY.name in PARAM_DICT["explorer"]:
            explorer = chainerrl.explorers. \
                LinearDecayEpsilonGreedy(start_epsilon=1.0,
                                         end_epsilon=0.05,
                                         decay_steps=100,
                                         random_action_func=self.env.get_random_action)
        elif DQNSettings.BOLTZMANN_EXPLORATION.name in PARAM_DICT["explorer"]:
            explorer = chainerrl.explorers.Boltzmann(T=PARAM_DICT["boltzmann_temperature"])
        elif DQNSettings.NOISY_NETS.name in PARAM_DICT["explorer"]:
            links.to_factorized_noisy(q_func, sigma_scale=0.5)  # Sigma from chainerrl rainbow
            explorer = chainerrl.explorers.Greedy()  # Turn off explorer (because of Noisy Nets)
        assert explorer is not None

        replay_buffer = None
        if DQNSettings.REPLAY_BUFFER.name in PARAM_DICT["replay_buffer"]:
            replay_buffer = chainerrl.replay_buffer.ReplayBuffer(capacity=PARAM_DICT["replay_buffer_capacity"])
        elif DQNSettings.PRIORITIZED_REPLAY_BUFFER.name in PARAM_DICT["replay_buffer"]:
            betasteps = PARAM_DICT["max_turns"] * PARAM_DICT["episodes"]
            replay_buffer = chainerrl.replay_buffer.PrioritizedReplayBuffer(
                capacity=PARAM_DICT["replay_buffer_capacity"],
                alpha=0.6,
                beta0=0.4,
                betasteps=betasteps,  # max_turns*episodes
                eps=0.01,
                normalize_by_max=True,
                error_min=0,
                error_max=1,
                num_steps=1)
        assert replay_buffer is not None

        phi = lambda obs: obs.astype(np.float32, copy=False)

        agent = None
        if DQNSettings.ALGO_DQN.name in PARAM_DICT["agent"]:
            agent = chainerrl.agents.DoubleDQN(q_function=q_func,
                                               optimizer=optimizer,
                                               replay_buffer=replay_buffer,
                                               explorer=explorer,
                                               gamma=PARAM_DICT["dqn_gamma"],
                                               replay_start_size=PARAM_DICT["replay_start_size"],
                                               update_interval=PARAM_DICT["update_interval"],
                                               target_update_interval=PARAM_DICT["target_update_interval"],
                                               phi=phi)
        elif DQNSettings.ALGO_DISTDQN.name in PARAM_DICT["agent"]:
            agent = chainerrl.agents.CategoricalDoubleDQN(q_function=q_func,
                                                          optimizer=optimizer,
                                                          replay_buffer=replay_buffer,
                                                          gamma=PARAM_DICT["dqn_gamma"],
                                                          explorer=explorer,
                                                          minibatch_size=PARAM_DICT["minibatch_size"],
                                                          replay_start_size=PARAM_DICT["replay_start_size"],
                                                          target_update_interval=PARAM_DICT["target_update_interval"],
                                                          update_interval=PARAM_DICT["update_interval"],
                                                          batch_accumulator=PARAM_DICT["batch_accumulator"],
                                                          phi=phi,
                                                          )
        assert agent is not None
        return agent

    # ACER agent was used in Gym Malware Environment. In this framework, however, it is not tested throughout
    def create_acer_agent(self):
        model = chainerrl.agents.acer.ACERSeparateModel(
            pi=links.Sequence(
                L.Linear(self.obs_size, 1024, initialW=LeCunNormal(1e-3)),
                F.relu,
                L.Linear(1024, 512, initialW=LeCunNormal(1e-3)),
                F.relu,
                L.Linear(512, self.n_actions, initialW=LeCunNormal(1e-3)),
                SoftmaxDistribution),
            q=links.Sequence(
                L.Linear(self.obs_size, 1024, initialW=LeCunNormal(1e-3)),
                F.relu,
                L.Linear(1024, 512, initialW=LeCunNormal(1e-3)),
                F.relu,
                L.Linear(512, self.n_actions, initialW=LeCunNormal(1e-3)),
                DiscreteActionValue),
        )

        opt = rmsprop_async.RMSpropAsync(lr=7e-4, eps=1e-2, alpha=0.99)
        opt.setup(model)
        opt.add_hook(chainer.optimizer.GradientClipping(40))

        replay_buffer = EpisodicReplayBuffer(128)

        phi = lambda obs: obs.astype(np.float32, copy=False)

        agent = chainerrl.agents.ACER(model, opt,
                                      gamma=PARAM_DICT["dqn_gamma"],  # reward discount factor
                                      t_max=32,  # update the model after this many local steps
                                      replay_buffer=replay_buffer,
                                      n_times_replay=4,  # number of times experience replay is repeated for each update
                                      replay_start_size=64,
                                      # don't start replay unless we have this many experiences in the buffer
                                      disable_online_update=True,  # rely only on experience buffer
                                      use_trust_region=True,  # enable trust region policy optimiztion
                                      trust_region_delta=0.1,  # a parameter for TRPO
                                      truncation_threshold=5.0,  # truncate large importance weights
                                      beta=1e-2,  # entropy regularization parameter
                                      phi=phi)

        return agent

    def make_action(self, state, reward, train=True):
        if train:
            return self.agent.act_and_train(state, reward)

        return self.agent.act(state)

    def stop_episode_and_train(self, state, reward, done):
        self.agent.stop_episode_and_train(state, reward, done)

    def stop_episode(self):
        self.agent.stop_episode()

    def save_existing_agent(self, directory_agent):
        self.agent.save(directory_agent)
        distutils.dir_util.copy_tree(directory_agent, PARAM_DICT['save_agent']+'last/')

    def print_debug(self):
        print("RL AGENT: " + str(PARAM_DICT["name"]))
        print("Statistics: ", self.agent.get_statistics())


# See https://github.com/endgameinc/gym-malware/blob/master/train_agent_chainer.py
class QFunction(chainer.Chain):
    def __init__(self, obs_size, n_actions):
        super(QFunction, self).__init__()
        n_hidden_channels = PARAM_DICT["dqn_hidden_size"]
        net = []
        inp_dim = obs_size
        for i, n_hid in enumerate(n_hidden_channels):
            net += [('l{}'.format(i), L.Linear(inp_dim, n_hid))]
            net += [('norm{}'.format(i), L.BatchNormalization(n_hid))]
            net += [('_act{}'.format(i), F.relu)]
            inp_dim = n_hid

        net += [('output', L.Linear(inp_dim, n_actions))]

        with self.init_scope():
            for n in net:
                if not n[0].startswith('_'):
                    setattr(self, n[0], n[1])

        self.forward = net

    def __call__(self, x, test=False):
        """
        Args:
            x (ndarray or chainer.Variable): An observation
            test (bool): a flag indicating whether it is in test mode
        """
        for n, f in self.forward:
            if not n.startswith('_'):
                x = getattr(self, n)(x)
            else:
                x = f(x)

        return chainerrl.action_value.DiscreteActionValue(x)


class Logger:
    """
        Logger class to write data during training/evaluation to a csv file
        It also creates a training or evaluation report at the end that summarizes the results.
        The report also contains the current version of the PARAM_DICT to make the experiments reproducible
    """
    def __init__(self, directory_to_save, evaluate):
        self.directory = directory_to_save
        self.adversarial_samples = []
        self.values_of_one_file = []
        if evaluate:
            self.data_file_name = PARAM_DICT["name"] + "_" + str(PARAM_DICT["threshold"]) + "_eval_data.csv"
        else:
            self.data_file_name = PARAM_DICT["name"] + "_train_data.csv"

    def reset_after_error(self):
        self.values_of_one_file = []

    def log_turn_values(self, detection_value, reward, turn, episode, adversarial, actions_taken, malware):
        self.values_of_one_file.append((detection_value, reward, turn, episode, adversarial, actions_taken, malware))
        if adversarial:
            self.adversarial_samples.append(
                (detection_value, reward, turn, episode, adversarial, actions_taken, malware))

    def write_sample_values_to_file(self):
        # Initial create
        if not os.path.isfile(self.directory + self.data_file_name):
            data_report = open(self.directory + self.data_file_name, 'w')
            data_report.write("detection_value,reward,turn,episode,adversarial,actions_taken,malware")
            data_report.close()

        data_report = open(self.directory + self.data_file_name, 'a')
        for detection_value, reward, turn, episode, adversarial, actions_taken, malware in self.values_of_one_file:
            data_report.write("\n")
            adver_value = "1" if adversarial else "0"
            actions_string = str(actions_taken).replace("'", "").replace(",", ";")
            report_string = str(detection_value) + "," + str(reward) + "," + str(turn) + "," + str(episode) + "," + \
                            str(adver_value) + "," + actions_string + "," + str(malware).split("/")[-1]
            data_report.write(report_string)
        data_report.close()
        self.values_of_one_file = []

    def save_agent_training_test_report(self, total_time, average_q, average_loss, agent_number_updates):
        type_dict = PARAM_DICT.copy()
        for key in type_dict:
            type_dict[key] = type(PARAM_DICT[key])
        with open(self.directory + str(PARAM_DICT["name"]) + "_training_report.csv", 'w') as agent_report:
            w = csv.DictWriter(agent_report, PARAM_DICT.keys())
            w.writeheader()
            w.writerow(PARAM_DICT)
            w.writerow(type_dict)

            pref_act_vector = self._calculate_most_often_used_action_vector()

            agent_report.write("\nAverage Q: " + str(average_q))
            agent_report.write("\nAverage Loss: " + str(average_loss))
            agent_report.write("\nNumber Updates Agent: " + str(agent_number_updates))
            agent_report.write("\nPreferred Action Vector: " + str(pref_act_vector))
            agent_report.write("\nTotal Time: " + str(total_time))
            agent_report.write("\nNumber adversarial samples: " + str(len(self.adversarial_samples)))
            agent_report.close()

            # Add a copy of the reports to the last/ dir
            distutils.dir_util.copy_tree(self.directory, PARAM_DICT['save_report']+'training_reports/last/')

    def save_agent_evaluation_report(self, total_time, number_errored, average_q, average_loss, agent_number_updates):
        if not os.path.isdir(PARAM_DICT["save_report"] + "evaluating_reports/"):
            os.mkdir(PARAM_DICT["save_report"] + "evaluating_reports/")
        with open(str(PARAM_DICT["save_report"] + "evaluating_reports/" + str(PARAM_DICT["name"]) + "_" + str(PARAM_DICT["threshold"]) + "_evaluation_report.csv"), 'w') as agent_report:
            w = csv.DictWriter(agent_report, PARAM_DICT.keys())
            w.writeheader()
            w.writerow(PARAM_DICT)

            pref_act_vector = self._calculate_most_often_used_action_vector()

            agent_report.write("\nAverage Q: " + str(average_q))
            agent_report.write("\nAverage Loss: " + str(average_loss))
            agent_report.write("\nNumber Updates Agent: " + str(agent_number_updates))
            agent_report.write("\nPreferred Action Vector: " + str(pref_act_vector))
            agent_report.write("\nTotal Time: " + str(total_time))
            agent_report.write("\nNumber adversarial samples: " + str(len(self.adversarial_samples)))
            agent_report.write("\nNumber errored: " + str(number_errored))
            agent_report.close()

    def _calculate_most_often_used_action_vector(self):
        actions = [act for (v, re, t, r, adv, act, ma) in self.adversarial_samples]
        if not actions:
            return []
        return max(actions, key=actions.count)


def _create_env(malware_path, malware_detection_function, malware_analysis_function):
    try:
        samples = os.listdir(malware_path)
        for i in range(len(samples)):
            samples[i] = malware_path + samples[i]
    except NotADirectoryError:
        samples = [malware_path]  # Only test one sample

    env = MalwareEnv(malware_list=samples,
                     detection_function=malware_detection_function,
                     analysis_function=malware_analysis_function)
    return env


# Creates the directories where the training and evaluation data, as well as the agent is stored
def _make_saving_directories():
    if not os.path.isdir(PARAM_DICT["save_report"] + "training_reports/"):
        os.mkdir(PARAM_DICT["save_report"] + "training_reports/")
    date_and_time_now = str(datetime.now()).split(".")[0].replace(" ", "-").replace(":", "-")[0:-3]  # no seconds

    directory_logging = PARAM_DICT["save_report"] + "training_reports/" + date_and_time_now + "/"
    os.makedirs(directory_logging)
    directory_agent = PARAM_DICT["save_agent"] + date_and_time_now + "/"
    os.makedirs(directory_agent)
    return directory_logging, directory_agent


# Creates a new agent and trains it with the current parameters from the PARAM_DICT
def train_and_save_agent(malware_detection, malware_analysis):
    directory_logging, directory_agent = _make_saving_directories()
    malware_detection_function = lambda sample: malware_detection(sample=sample,
                                                                  model=PARAM_DICT["detection_model"],
                                                                  threshold=PARAM_DICT["threshold"])
    # Environment:
    env = _create_env(malware_path=PARAM_DICT["malware_path"],
                      malware_detection_function=malware_detection_function,
                      malware_analysis_function=malware_analysis)
    state = env.reset()
    env.render()
    # Agent:
    agent = RlAgent(environment=env)
    # agent.print_debug()

    # Logger:
    logger = Logger(directory_to_save=directory_logging,
                    evaluate=False)
    start_time = time()

    # TRAIN:
    episodes = PARAM_DICT["episodes"]
    episode = 1
    while episode <= episodes:
        print("\n### Training # Episode: {} of {} ###".format(episode, episodes))
        current_turn = 0
        reward, episode_over, info, errored = 0, False, {}, False
        while not episode_over:
            current_turn += 1
            action = agent.make_action(state, reward, train=True)
            print('\n## Turn: {} # Next action: {} ##'.format(current_turn, ACTIONS[action]))
            state, reward, episode_over, info = env.step(action)
            print("Reward in turn " + str(current_turn) + " : " + str(reward))
            env.render()

            detected = info["detected"]
            detection_value = info["detected_confidence"]
            errored = info["errored"]  # LIEF ERRORS DURING MANIPULATION (True/False)
            if not errored:
                logger.log_turn_values(detection_value=detection_value,
                                       reward=reward,
                                       turn=current_turn,
                                       episode=episode,
                                       adversarial=not detected,
                                       actions_taken=_map_action_indices_to_actions(env.actions_taken),
                                       malware=env.current_malware)
            elif errored:
                episode -= 1  # Ignore this episode
                print('Episode ignored due to manipulation errors. Restarting..')

        if not errored:
            agent.stop_episode_and_train(state, reward, episode_over)
            logger.write_sample_values_to_file()
        else:
            agent.stop_episode()  # Do not train on errored malware
            logger.reset_after_error()

        state = env.reset()
        # print("Episode ended after " + str(current_turn) + " turns")
        # print("Reward after episode: " + str(reward) + "\n")

        episode += 1

    print("Training finished!")
    agent.save_existing_agent(directory_agent)
    avg_q = agent.agent.get_statistics()[0][1]
    avg_loss = agent.agent.get_statistics()[1][1]
    number_updates = agent.agent.get_statistics()[2][1]
    logger.save_agent_training_test_report(total_time=f.time_me(start_time),
                                           average_q=avg_q,
                                           average_loss=avg_loss,
                                           agent_number_updates=number_updates)
    return directory_logging


# Loads the PARAM_DICT associated with an agent (in training report)
def _load_agent_information(agent_information):
    global PARAM_DICT # Check
    # Load Dictionary:
    with open(agent_information, 'r') as file:
        r = csv.DictReader(file)
        loaded_dicts = [dict(d) for d in r]
        PARAM_DICT = loaded_dicts[0]
        type_dict = loaded_dicts[1]

        for key in PARAM_DICT:
            type_of_key_str = type_dict[key]
            if "int" in type_of_key_str:
                type_of_key = int
            elif "bool" in type_of_key_str:
                type_of_key = bool
            elif "float" in type_of_key_str:
                type_of_key = float
            elif "list" in type_of_key_str:
                type_of_key = list
            else:
                type_of_key = None
            if type_of_key is not None:
                if type_of_key == list:
                    list_from_dict = str(PARAM_DICT[key]).replace("[", "").replace("]", "").split(",")
                    map_to = int
                    if "." in list_from_dict[0]:
                        map_to = float
                    PARAM_DICT[key] = list(map(map_to, list_from_dict))
                elif type_of_key == bool:
                    PARAM_DICT[key] = True if "True" in PARAM_DICT[key] else False
                else:
                    PARAM_DICT[key] = type_of_key(PARAM_DICT[key])


# Evaluates a given agent against the model from the malware_detection function
# Malware analysis can be optionally applied after the evaluation on successful adversarial examples
def load_and_evaluate_agent(directory_agent, agent_information, evaluation_set_directory,
                            malware_detection, malware_analysis):
    _load_agent_information(agent_information=agent_information)

    malware_detection_function = lambda sample: malware_detection(sample=sample,
                                                                  model=PARAM_DICT["detection_model"],
                                                                  threshold=PARAM_DICT["threshold"])
    # Env
    env = _create_env(malware_path=evaluation_set_directory,
                      malware_detection_function=malware_detection_function,
                      malware_analysis_function=malware_analysis)
    state = env.reset()

    # Agent
    agent = RlAgent(environment=env)
    agent.agent.load(directory_agent)
    # agent.print_debug()

    # Logger:
    logger = Logger(directory_to_save=directory_agent, evaluate=True)
    start_time = time()

    # MANIPULATE:
    episodes = len(env.malware_list)
    episode = 1
    number_errored = 0
    while episode <= episodes:
        print("\n### Evaluation # Episode: {} of {} ###".format(episode, episodes))
        current_turn = 0
        reward, episode_over, info, errored = 0, False, {}, False
        while not episode_over:
            current_turn += 1
            action = agent.make_action(state, reward, train=False)
            print('\n## Turn: {} # Next action: {} ##'.format(current_turn, ACTIONS[action]))
            state, reward, episode_over, info = env.step(action)
            env.render()
            # print("Action from agent: " + ACTIONS[action])
            print("Reward in turn " + str(current_turn) + " : " + str(reward))

            detected = info["detected"]
            detection_value = info["detected_confidence"]
            errored = info["errored"]  # LIEF ERRORS DURING MANIPULATION (True/False)
            if not errored:
                logger.log_turn_values(detection_value=detection_value,
                                       reward=reward,
                                       turn=current_turn,
                                       episode=episode,
                                       adversarial=not detected,
                                       actions_taken=_map_action_indices_to_actions(env.actions_taken),
                                       malware=env.current_malware)

            # Episode does not get decreased (-= 1) like in training, rather we save how many errors we got
            elif errored:
                number_errored += 1

        agent.stop_episode()
        if not errored:
            logger.write_sample_values_to_file()
        else:
            logger.reset_after_error()

        state = env.reset()
        # print("Episode ended after " + str(current_turn) + " turns")
        # print("Reward after episode: " + str(reward) + "\n")

        episode += 1

    print("\nNumber errored: ", number_errored)
    print("Evaluation finished!")
    avg_q = agent.agent.get_statistics()[0][1]
    avg_loss = agent.agent.get_statistics()[1][1]
    number_updates = agent.agent.get_statistics()[2][1]
    logger.save_agent_evaluation_report(total_time=f.time_me(start_time),
                                        number_errored=number_errored,
                                        average_q=avg_q,
                                        average_loss=avg_loss,
                                        agent_number_updates=number_updates)


def _map_action_indices_to_actions(actions_taken):
    actions = []
    for index in actions_taken:
        actions.append(ACTIONS[index])
    return actions


PARAM_DICT = {
    "name": "AIMEDRL",
    "seed": 1234,
    "save_report": "db/rl/",
    "save_agent": "samples/rl/agent/",
    "malware_path": "samples/malware_set/",
    "episodes": 1000,
    "detection_model": "LightGBM",
    "threshold": 0.9,
    "max_turns": 10,
    "strategy_reset": True,
    "strategy_inject": False,
    "maximum_reward": 10,
    "weights": STANDARD_WEIGHTS,
    "reward_punishment": True,
    "agent": DQNSettings.ALGO_DISTDQN.name,
    "optimizer": DQNSettings.ADAM_OPTIMIZER.name,
    "adam_epsilon": 1e-2,
    "dqn_gamma": 0.95,
    "dqn_replay_start_size": 32,
    "replay_buffer": DQNSettings.PRIORITIZED_REPLAY_BUFFER.name,
    "replay_buffer_capacity": 1000,
    "dqn_hidden_size": [64, 16],
    "explorer": DQNSettings.NOISY_NETS.name,
    "epsilon_greedy_start_epsilon": 1.0,
    "epsilon_greedy_end_epsilon": 0.05,
    "epsilon_greedy_decay_steps": 100,
    "boltzmann_temperature": 1.0,
    "replay_start_size": 32,
    "minibatch_size": 32,
    "batch_accumulator": "mean",
    "update_interval": 1,
    "target_update_interval": 100
}
