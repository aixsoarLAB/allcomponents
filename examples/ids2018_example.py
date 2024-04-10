import sys

# 將包含 deeplog 模組的目錄路徑添加到 sys.path
sys.path.append('../DeepLog/deeplog')
# import DeepLog and Preprocessor
from deeplog              import DeepLog
from preprocessor import Preprocessor
# Import pytorch
import torch

##############################################################################
#                                 Load data                                  #
##############################################################################

# Create preprocessor for cd loading data
preprocessor = Preprocessor(
    length  = 10,           # Extract sequences of 20 items
    timeout = float('inf'), # Do not include a maximum allowed time between events
)

training_data_path = "./data/IDS2018_train_benign"

# Load data from csv file
#X, y, label, mapping = preprocessor.csv(training_data_path)
# Load data from txt file
X, y, label, mapping = preprocessor.text(training_data_path)

print("X:", X, "\nShape:", X.shape, "\nmapping:", mapping)

##############################################################################
#                                  DeepLog                                   #
##############################################################################

# Create DeepLog object
deeplog = DeepLog(
    input_size  = 60, # Number of different events to expect
    hidden_size = 64 , # Hidden dimension, we suggest 64
    output_size = 100, # Number of different events to expect
)

# Optionally cast data and DeepLog to cuda, if available
if torch.cuda.is_available():
    deeplog = deeplog.to("cuda")
    X       = X      .to("cuda")
    y       = y      .to("cuda")

# Train deeplog
deeplog.fit(
    X          = X,
    y          = y,
    epochs     = 3,
    batch_size = 128,
)

##############################################################################
#                                  Predict                                   #
##############################################################################
def predict_and_evaluate(preprocessor, deeplog, data_path, k=9):
    """
    使用 DeepLog 模型對指定路徑的數據進行預測並評估異常率。

    參數：
    - preprocessor: Preprocessor 的實例。
    - deeplog: DeepLog 的實例。
    - data_path: 要進行預測的數據文件路徑。
    - k: 預測時考慮的最可能事件數量。

    返回：
    - abnormal_rate: 計算得到的異常率。
    """
    # Load data from text file
    Xp, yp, label, mapping_p = preprocessor.text(data_path, verbose=True)
    print("Xp:", Xp, "\nShape:", Xp.shape, "\nmapping_p:", mapping_p)

    # Predict using deeplog
    y_pred, confidence = deeplog.predict(X=Xp, k=k)
    print("y_pred:", y_pred, "\nshape:", y_pred.shape)

    # Load test data for comparison
    with open(data_path, 'r') as file:
        data = file.readlines()

    cleaned_data = [item.strip() for item in data]
    data = [item for sublist in cleaned_data for item in sublist.split()]

    print("data:", data, "\nsize:", len(data))

    # Reverse the mapping
    reverse_mapping = {v: k for k, v in mapping_p.items()}

    # Map the events
    mapped_data = [reverse_mapping[int(event)] for event in data]

    print("mapped_data:", mapped_data, "\nsize:", len(mapped_data))

    # Initialize a list for comparison results
    results = [1 if reverse_mapping[int(data[i])] in y_pred[i] else 0 for i in range(len(mapped_data))]

    print("results:", results, "\nsize:", len(results))

    # Calculate abnormal rate
    num_of_zero = results.count(0)
    abnormal_rate = num_of_zero / len(results)

    print("異常率：%.3f" %abnormal_rate)
    print("predict file: %s" %data_path)

    return abnormal_rate

# 使用範例
data_paths = ["./data/IDS2018_test_abnormal_Infiltration", "./data/IDS2018_test_abnormal_Bot"]

for data_path in data_paths:
    predict_and_evaluate(preprocessor, deeplog, data_path, k=9)
    print("training file: %s" %training_data_path)