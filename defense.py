#!/usr/bin/env python3
import os
import time
import joblib
import numpy as np
import config as cfg
import functions as f
import lightgbm as lgb
from sklearn.metrics import roc_auc_score
from data.pefeatures import PEFeatureReader
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression


NPZ_PATH = cfg.file['paths']['npz']
MODEL_PATH = cfg.file['paths']['model_path']
VECTORIZED_PATH = cfg.file['paths']['vectorized_path']


class Defense:

    def __init__(self, model, csv_path, features_path, number_examples):
        self.model = model
        self.csv_path = csv_path
        self.features_path = features_path
        self.number_examples = number_examples

    @staticmethod
    def create_uap_datasets(csv_path, features_path, uap_vector):
        """
            Apply UAP to exploration set to validate results from exploration set.
            Create two feature-space datasets:
            i) original examples (before UAP injection)
            ii) adversarial examples (after injecting UAP)

            Input:
                csv_path: path to load CSV file with malware examples
                features_path: path to save features from examples
                uap_vector: UAP vector calculated using model and dataset
        """

        # Save features from problem-space malware
        f.save_features_malware(csv_path=csv_path, features_path=features_path, pert_vector=uap_vector)

    @staticmethod
    def extract_perturbation_from_features(features_path):
        """
            Extract noise / perturbation from features of adversarial examples
            subtracted from the original malware it was generated from.
            i) Load original and adversarial datasets (features)
            ii) Subtract original - adversarial leaving only noise

            Input:
                features_path: path to load features from examples
        """
        # Load datasets of original & adversarial examples to extract noise
        adv_examples = np.load(features_path + 'adv_examples_uap_compress.npz')
        original_malware = np.load(features_path + 'orig_files_uap_compress.npz')

        # Extract features
        features_adv_examples = np.array(adv_examples['features'])
        features_original = np.array(original_malware['features'])

        # Calculate noise / perturbation based on adversarial - original malware
        noise = features_adv_examples - features_original

        return noise

    # DEFENSE

    # Define statistical model to generate adversarial examples
    @staticmethod
    def attack_statistical_model(malware_input, noise):
        """
            Define statistical model to approximate noise / perturbations.
            Author: Luis Munoz Gonzalez

            Input:
                malware_input: batch of malware examples
                noise: perturbation injected to generate adversarial examples
        """
        # Number of features
        number_features = malware_input.shape[1]

        # Define mean and standard var
        meanV = np.zeros(number_features)
        stdV = np.zeros(number_features)

        # Assign value to meanV and stdV
        for each_feat in range(number_features):
            meanV[each_feat] = np.mean(noise[:, each_feat])
            stdV[each_feat] = np.std(noise[:, each_feat])

        # Generate adversarial examples
        adv_ex = np.zeros(malware_input.shape)
        for e in range(meanV.size):
            rd = np.random.randn(malware_input.shape[0]) * stdV[e] + meanV[e]
            adv_ex[:, e] = malware_input[:, e] + rd

        return adv_ex

    def generate_adv_examples_statistical_model(self, malware_batch, noise, npz_path):
        """
            Generate adversarial examples using statistical model that approximates
            a function based on the noise extracted from the features (in this case Gaussian)
        """
        # Load adversarial examples or generate them using statistical model
        if os.path.exists(npz_path + 'adversarial_examples_approximated.npz'):
            adv_examples_approximated = np.load(npz_path + 'adversarial_examples_approximated.npz')
            adv_examples_approximated = adv_examples_approximated['features']

        else:
            # Generate same number of adversarial examples as malicious
            adv_examples_approximated = self.attack_statistical_model(malware_batch, noise)

            # Saving adversarial examples generated with the statistical model above
            np.savez(npz_path + 'adversarial_examples_approximated.npz', features=adv_examples_approximated)

        print('Adversarial data shape:', adv_examples_approximated.shape)
        return adv_examples_approximated

    def adversarial_training(self, noise):
        """
            Perform adversarial training using 1/2 of dataset with adversarial
            examples + 1/2 with benign (pure) or 1/4 of dataset with adversarial
            examples + 1/4 with malicious, and 1/2 of dataset benign (mixed).
            Also, train a baseline model to use as a benchmark.

            i) Baseline: Train model with N malware and N benign examples.

            ii) Pure: Adversarially-train model
                a) generate N adversarial samples with statistical model
                b) Train using N statistically-generated adversarial examples
                and N benign examples.

            iii) Mixed: Adversarially-train model
                a) generate N/2 adversarial samples with statistical model
                b) Train using N/2 statistically-generated adversarial examples,
                50k malware and N benign examples.

            Input:
                noise: information sampled from features of adversarial examples and original files

        """

        # Define size of malicious, benign, and adversarial datasets
        # number_examples = 50000

        # Load EMBER data
        print('Loading datasets to train baseline & adversarial models: ')
        feature_reader = PEFeatureReader()
        X_train, y_train = feature_reader.read_vectorized_features(VECTORIZED_PATH, 'train', feature_version=1)
        if self.number_examples == 50000:
            start_examples = 38800
            end_examples = 189000
            X_train = X_train[start_examples:end_examples]
            y_train = y_train[start_examples:end_examples]
        print('Original features shape:', X_train.shape)

        # Filter only malicious
        malicious_rows = (y_train == 1)
        malware_batch = X_train[malicious_rows]
        malware_batch = malware_batch[:self.number_examples]
        print('Malicious features shape:', malware_batch.shape)

        # Filter only benign
        benign_rows = (y_train == 0)
        benign_batch = X_train[benign_rows]
        benign_batch = benign_batch[:self.number_examples]
        print('Benign features shape:', benign_batch.shape)

        # Generate adversarial examples for adversarial training
        adversarial_batch = self.generate_adv_examples_statistical_model(malware_batch, noise, npz_path=NPZ_PATH)

        print('\na) Train LGBM baseline with {} malicious and {} benign files'.format(self.number_examples,
                                                                                      self.number_examples))

        # Define datasets for baseline training

        # Load model if they already exist, otherwise train them
        if os.path.exists(MODEL_PATH + 'ember_model_baseline.pkl'):
            lgbm_model_baseline = joblib.load(MODEL_PATH + 'ember_model_baseline.pkl')

        else:

            X_train = np.concatenate((malware_batch, benign_batch), axis=0)
            y_train = np.concatenate((np.ones(self.number_examples), np.zeros(self.number_examples)), axis=0)
            print('Train data shape for baseline model:', X_train.shape)

            # Create dataset for training
            lgbm_dataset = lgb.Dataset(X_train, y_train)
            print('Finished preparing dataset for training.')

            # Define parameters & train
            start_training = time.time()
            params = {"application": "binary"}
            lgbm_model_baseline = lgb.train(params, lgbm_dataset)
            print('Training time: {} mins'.format(round((time.time() - start_training) / 60, 2)))

            lgbm_model_baseline.save_model(MODEL_PATH + 'ember_model_baseline.txt')
            joblib.dump(lgbm_model_baseline, MODEL_PATH + 'ember_model_baseline.pkl')
            print('Baseline model saved.')

        print('b) Adversarial train (Pure) LGBM with {} adversarial and {} benign  files'.format(self.number_examples,
                                                                                                 self.number_examples))

        # Define dataset for adversarially trained model 'pure' (AEs und benign)

        # Load model if they already exist, otherwise train them
        if os.path.exists(MODEL_PATH + 'ember_model_adv_trained_pure.pkl'):
            lgbm_model_adv_trained_pure = joblib.load(MODEL_PATH + 'ember_model_adv_trained_pure.pkl')

        else:

            X_train = np.concatenate((adversarial_batch, benign_batch), axis=0)
            y_train = np.concatenate((np.ones(self.number_examples), np.zeros(self.number_examples)), axis=0)
            print('Train data shape for pure adversarial model:', X_train.shape)

            # Create dataset for training
            lgbm_dataset = lgb.Dataset(X_train, y_train)
            print('Finished preparing dataset for training.')

            # Define parameters & train
            start_training = time.time()
            params = {"application": "binary"}
            lgbm_model_adv_trained_pure = lgb.train(params, lgbm_dataset)
            print('Training time: {} mins'.format(round((time.time() - start_training) / 60, 2)))

            lgbm_model_adv_trained_pure.save_model(MODEL_PATH + 'ember_model_adv_trained_pure.txt')
            joblib.dump(lgbm_model_adv_trained_pure, MODEL_PATH + 'ember_model_adv_trained_pure.pkl')
            print('Adversarially trained (pure) model saved.')

        # Define dataset for adversarially trained model 'mixed' (AEs + malware und benign)

        print('c) Adversarial train (Mixed) LGBM with {} adversarial, {} malicious, and {} benign files'.format(
            int(self.number_examples / 2), int(self.number_examples / 2), self.number_examples))

        # Load model if they already exist, otherwise train them
        if os.path.exists(MODEL_PATH + 'ember_model_adv_trained_mixed.pkl'):
            lgbm_model_adv_trained_mixed = joblib.load(MODEL_PATH + 'ember_model_adv_trained_mixed.pkl')

        else:
            number_examples_mal_adv = int(self.number_examples / 2)
            X_train = np.concatenate(
                (malware_batch[:number_examples_mal_adv], adversarial_batch[:number_examples_mal_adv], benign_batch),
                axis=0)
            y_train = np.concatenate((np.ones(self.number_examples), np.zeros(self.number_examples)), axis=0)
            print('Train data shape for mixed adversarial model:', X_train.shape)

            # Create dataset for training
            lgbm_dataset = lgb.Dataset(X_train, y_train)
            print('Finished preparing dataset for training.')

            # Define params & train | with feature_version = 1 (2351)
            start_training = time.time()
            params = {"application": "binary"}
            lgbm_model_adv_trained_mixed = lgb.train(params, lgbm_dataset)
            print('Training time: {} mins'.format(round((time.time() - start_training) / 60, 2)))

            lgbm_model_adv_trained_mixed.save_model(MODEL_PATH + 'ember_model_adv_trained_mixed.txt')
            joblib.dump(lgbm_model_adv_trained_mixed, MODEL_PATH + 'ember_model_adv_trained_mixed.pkl')
            print('Adversarially trained (mixed) model saved.')

        return lgbm_model_baseline, lgbm_model_adv_trained_pure, lgbm_model_adv_trained_mixed

    def train_logit(self, model_path):
        """
            Training a logistic regression model.

            Input:
                model_path: path to save & load trained logit model
        """
        time_all = time.time()

        # Load EMBER data
        print('\nLoading datasets to train LR model: ')
        feature_reader = PEFeatureReader()
        X_train, y_train, X_test, y_test = feature_reader.read_vectorized_features(VECTORIZED_PATH, feature_version=1)
        if self.number_examples == 50000:
            start_examples = 38800
            end_examples = 189000
            X_train = X_train[start_examples:end_examples]
            y_train = y_train[start_examples:end_examples]
        print('Original features shape:', X_train.shape)

        # Selecting less samples to avoid crashing if working with notebook
        # minvalue = 0
        # maxvalue = 900000 # Für 100.000 mit AUC 0.94.
        # X_train = X_train[minvalue:maxvalue]
        # y_train = y_train[minvalue:maxvalue]
        # print('Current data shape:', X_train.shape)

        # Filter out unlabeled
        train_rows = (y_train != -1)
        X_train = X_train[train_rows]
        y_train = y_train[train_rows]
        print('Filtered features shape:', X_train.shape)

        # If trained data reduced adjust test data
        if self.number_examples == 50000:
            test_examples = 30000
            X_test = X_test[:test_examples]
            y_test = y_test[:test_examples]
        print('Test features shape:', X_test.shape)

        # Scale data
        norm_std_scaler = StandardScaler().fit(X_train)
        X_train = norm_std_scaler.transform(X_train)
        X_test = norm_std_scaler.transform(X_test)

        # Load the pre-trained logit model
        if os.path.exists(model_path + 'logit_ember.pkl'):
            clf_LR = joblib.load(model_path + 'logit_ember.pkl')
        else:
            # Train the model on the dataset
            print('Model not found, LR will be trained..')
            clf_LR = LogisticRegression(random_state=24)
            clf_LR = clf_LR.fit(X_train, y_train)
            joblib.dump(clf_LR, model_path + 'logit_ember.pkl')

            # Show processing time in h:m:s
            m, s = divmod(time.time() - time_all, 60)
            h, m = divmod(m, 60)
            print("Time elapsed training logit: %d:%02d:%02d" % (h, m, s))

        # Calculate predictions with LR model
        print("Model {}".format(clf_LR.__class__.__name__))
        y_pred = clf_LR.predict(X_test)
        print("ROC-AUC LR:", roc_auc_score(y_test, y_pred))

        return clf_LR

    @staticmethod
    def extract_important_features(model, features_path):
        """
            Extract most important features of logit model.
        """
        # Get importance weights for LR model
        importance = model.coef_
        importance = importance[0]

        # Collect more indexes for features with same weight of importance (excluding features = 0)
        repeated_indexes = []
        repeated_values = []
        for i, v in enumerate(importance):
            curr_repeated_indexes = [idx for idx in range(len(importance)) if importance[idx] == importance[i]]
            if len(curr_repeated_indexes) > 1 and v != 0:
                repeated_indexes.append(curr_repeated_indexes)
                repeated_values.append(v)

        if repeated_indexes:  # Only 46 if 0.0 is included as feature value (same weight)
            print(len(repeated_indexes), repeated_indexes)
            print(len(repeated_values), repeated_values)

        # Get n important features & indexes
        j = 474  # arbitrarily chosen ~20% of 2351
        top_j_features = sorted(importance, reverse=True)[:j]
        indices = [list(importance).index(value) for value in top_j_features]
        print('\nIdentified top 20% features based on feature importances of LR.')
        # print('Top {} values: {}'.format(j, top_j_features))
        # print('Top {} indexes: {}'.format(j, indices))
        print()

        np.savez(features_path + 'top_features_LR_importances_indices', indices)

        return indices

    def train_lgbm_important_features(self, features_path):
        """
            Train the LightGBM model with the EMBER dataset using only the top
            features based on the Logit most important features.

            Input:
                features_path: path to save features from examples
        """

        # Load EMBER data
        print('Loading datasets to train LGBM with feature reduction: ')
        feature_reader = PEFeatureReader()
        X_train, y_train, X_test, _ = feature_reader.read_vectorized_features(VECTORIZED_PATH, feature_version=1)
        if self.number_examples == 50000:
            start_examples = 38800
            end_examples = 189000
            X_train = X_train[start_examples:end_examples]
            y_train = y_train[start_examples:end_examples]
        print('Original features shape:', X_train.shape)

        # Filter unlabeled data
        train_rows = (y_train != -1)
        X_train = X_train[train_rows]
        y_train = y_train[train_rows]
        print('Filtered features shape:', X_train.shape)

        # If trained data reduced adjust test data
        if self.number_examples == 50000:
            test_examples = 30000
            X_test = X_test[:test_examples]
        print('Test features shape:', X_test.shape)

        # Use only 20% of highest importance features based on Logit model
        top_features_LR_importances = np.load(features_path + 'top_features_LR_importances_indices.npz')
        top_features_LR_importances = top_features_LR_importances['arr_0']
        X_train = X_train[:, top_features_LR_importances]
        print('Top 20% features shape:', X_train.shape)

        # Create dataset for training
        lgbm_dataset = lgb.Dataset(X_train, y_train)
        # print('Finished preparing dataset for training.\n')

        # Define parameters & train
        start_training = time.time()
        params = {"application": "binary"}
        lgbm_model_reduced = lgb.train(params, lgbm_dataset)
        print('Training time: {} mins'.format(round((time.time() - start_training) / 60, 2)))

        lgbm_model_reduced.save_model(MODEL_PATH + 'ember_model_reduced.txt')
        joblib.dump(lgbm_model_reduced, MODEL_PATH + 'ember_model_reduced.pkl')
        print('Feature-reduced model saved.\n')

        return lgbm_model_reduced

    def train_feature_reduction(self, model_path, features_path):
        """
          i) Train a Logistic Regression Model
         ii) Extract feature_importances from Logit
        iii) Retrain LGBM with 20% most important features
        """
        # Train Logit
        clf_LR = self.train_logit(model_path=model_path)

        # Extract feature_importances from Logit
        self.extract_important_features(model=clf_LR, features_path=features_path)

        # Retrain LGBM with 20% most important features
        self.train_lgbm_important_features(features_path=features_path)
