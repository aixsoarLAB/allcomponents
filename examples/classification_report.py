# Import DeepLog and Preprocessor
from deeplog              import DeepLog
from deeplog.preprocessor import Preprocessor
import torch
# Import classification report
from sklearn.metrics import classification_report
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import random
import tensorflow as tf

#random seed
np.random.seed(42)
random.seed(42)
tf.random.set_seed(42)
model = RandomForestClassifier(random_state=42)

##############################################################################
#                                 Load data                                  #
##############################################################################

# Create preprocessor for loading data
preprocessor = Preprocessor(
    length  = 20,           # Extract sequences of 20 items
    timeout = float('inf'), # Do not include a maximum allowed time between events
)

# Load data from HDFS dataset
X_train       , y_train       , label_train       , mapping_train        = preprocessor.text("./data/IDS2018_train_Benign"        , verbose=True)
X_test        , y_test        , label_test        , mapping_test         = preprocessor.text("./data/IDS2018_test_Benign"  , verbose=True)
X_test_anomaly, y_test_anomaly, label_test_anomaly, mapping_test_anomaly = preprocessor.text("./data/IDS2018_test_abnormal_Infiltration", verbose=True)
print(mapping_train)
print(mapping_test)
##############################################################################
#                                  DeepLog                                   #
##############################################################################

# Create DeepLog object
deeplog = DeepLog(
    input_size  = 60, # Number of different events to expect
    hidden_size = 64 , # Hidden dimension, we suggest 64
    output_size = 60, # Number of different events to expect
)

# Optionally cast data and DeepLog to cuda, if available
if torch.cuda.is_available():
    # Set deeplog to device
    deeplog = deeplog.to("cuda")

    # Set data to device
    X_train        = X_train       .to("cuda")
    y_train        = y_train       .to("cuda")
    X_test         = X_test        .to("cuda")
    y_test         = y_test        .to("cuda")
    X_test_anomaly = X_test_anomaly.to("cuda")
    y_test_anomaly = y_test_anomaly.to("cuda")

# Train deeplog
deeplog.fit(
    X          = X_train,
    y          = y_train,
    epochs     = 10,
    batch_size = 256,
    
)
#optimizer  = torch.optim.Adam,

# Predict normal data using deeplog
y_pred_normal, confidence = deeplog.predict(
    X = X_test,
    k = 9, # Change this value to get the top k predictions (called 'g' in DeepLog paper, see Figure 6)
)

# Predict anomalous data using deeplog
y_pred_anomaly, confidence = deeplog.predict(
    X = X_test_anomaly,
    k = 9, # Change this value to get the top k predictions (called 'g' in DeepLog paper, see Figure 6)
)

################################################################################
#                            Classification report                             #
################################################################################

print("Classification report - predictions")
print(classification_report(
    y_true = y_test.cpu().numpy(),
    y_pred = y_pred_normal[:, 0].cpu().numpy(),
    digits = 4,
    zero_division = 0,
))

################################################################################
#                             Check for anomalies                              #
################################################################################

# Check if the actual value matches any of the predictions
# If any prediction matches, it is not an anomaly, so to get the anomalies, we
# invert our answer using ~

# Check for anomalies in normal data (ideally, we should not find any)
anomalies_normal = ~torch.any(
    y_test == y_pred_normal.T,
    dim = 0,
)

# Check for anomalies in abnormal data (ideally, we should not find all)
anomalies_abnormal = ~torch.any(
    y_test_anomaly == y_pred_anomaly.T,
    dim = 0,
)

# Compute classification report for anomalies
y_pred = torch.cat((anomalies_normal, anomalies_abnormal))
y_true = torch.cat((
    torch.zeros(anomalies_normal  .shape[0], dtype=bool),
    torch.ones (anomalies_abnormal.shape[0], dtype=bool),
))

print("Classification report - anomalies")
print(classification_report(
    y_pred       = y_pred.cpu().numpy(),
    y_true       = y_true.cpu().numpy(),
    labels       = [False, True],
    target_names = ["Normal", "Anomaly"],
    digits       = 4,
))

mismatch_indices = (y_pred != y_true).nonzero().squeeze()
mismatch_samples_pred = y_pred[mismatch_indices]
mismatch_samples_true = y_true[mismatch_indices]

print("Mismatched samples:")
for i in range(len(mismatch_indices)):
    print(f"Index: {mismatch_indices[i]}, Predicted: {mismatch_samples_pred[i]}, True: {mismatch_samples_true[i]}")
