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
    length  = 20,           # Extract sequences of 20 items
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
    epochs     = 10,
    batch_size = 128,
)

##############################################################################
#                                  Predict                                   #
##############################################################################

data_path = "./data/IDS2018_test_abnormal_Infiltration"

# Load data from csv file
#Xp, yp, label, mapping_p = preprocessor.csv("/home/ubuntu/DeepLog/examples/data/hdfs_train")
# Load data from txt file
Xp, yp, label, mapping_p = preprocessor.text(data_path)
print("Xp:", Xp, "\nShape:", X.shape, "\nmapping_p:", mapping_p)

# Predict using deeplog
y_pred, confidence = deeplog.predict(
    X = Xp,
    k = 9,
)

print("y_pred:", y_pred, "\nshape:", y_pred.shape)

##############################################################################
#                                 Comparison                                 #
##############################################################################

# 讀取測試文件
with open(data_path, 'r') as file:
    data = file.readlines()

cleaned_data = [item.strip() for item in data]

# 使用列表推導式分隔每個字串，並將結果扁平化形成一個新的串列
data = [item for sublist in cleaned_data for item in sublist.split()]

print("data:", data, "\nsize:", len(data))

# 反轉 mapping，以便我們可以根據事件ID找到對應的編號
reverse_mapping = {v: k for k, v in mapping_p.items()}

# 轉換 events 列表中的每個字串為數字，然後根據 reverse_mapping 進行映射
mapped_data = [reverse_mapping[int(event)] for event in data]

print("mapped_data:", mapped_data, "\nsize:", len(mapped_data))

# 初始化一個零張量，用於存儲比較結果，長度與 test_normal_data 相同
results = []

# 遍歷 test_normal_data 的每一行
for i in range(0, len(mapped_data)):
    match = False
    for j in y_pred[i]:
        if mapped_data[i] == j:
            match = True
            break
    
    # 如果有匹配，設置結果為1
    if match:
        results.append(1)
    else:
        results.append(0)

print("results:", results, "\nsize:", len(results))

# 計算列表中0的數量
num_of_zero = results.count(0)
print("異常數量：%d" %num_of_zero)

# 計算機率
abnormal_rate = num_of_zero / len(results)

print("training data: %s" %training_data_path)
print("predict file: %s" %data_path)
print("異常率：%.3f" %abnormal_rate)