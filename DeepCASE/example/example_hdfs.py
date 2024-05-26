from sklearn.metrics import classification_report
import pandas as pd
import numpy as np
import torch
import random
import matplotlib

try:
    import tkinter
    matplotlib.use('TkAgg')
except ImportError:
    matplotlib.use('Agg')

import matplotlib.pyplot as plt

# DeepCASE Imports
from deepcase.preprocessing import Preprocessor
from deepcase.context_builder import ContextBuilder
from deepcase.interpreter import Interpreter




seed = 42
random.seed(seed)
np.random.seed(seed)
torch.manual_seed(seed)
if torch.cuda.is_available():
    torch.cuda.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)

if __name__ == "__main__":
    
    train_path = '/home/wang/project/allcomponents/DeepCASE/data/Wednesday-21-02-2018/Dsid/destination_ip_signatures_normal.txt'
    test_prth = '/home/wang/project/allcomponents/DeepCASE/data/Wednesday-21-02-2018/Ssid/source_ip_signatures_DDOS-LOIC-UDP.txt'

    ########################################################################
    #                             Loading data                             #
    ########################################################################

    # Create preprocessor
    preprocessor = Preprocessor(
        length  = 10,    # 10 events in context
        timeout = 86400, # Ignore events older than 1 day (60*60*24 = 86400 seconds)
    )

    # Load training data from file (Monday)
    context_train, events_train, labels_train, mapping_train = preprocessor.text(
        path    = train_path,
        verbose = True,
    )
    
    # Load testing data from file (Tuesday)
    context_test, events_test, labels_test, mapping_test = preprocessor.text(
        path    = test_prth ,
        verbose = True,
    )
    
    print(mapping_train)
    print(mapping_test)
    # In case no labels are provided for training, set labels_train to -1
    if labels_train is None:
        labels_train = np.full(events_train.shape[0], 0, dtype=int)

    # Cast to cuda if available
    if torch.cuda.is_available():
        events_train  = events_train.to('cuda')
        context_train = context_train.to('cuda')
        # In case no labels are provided for testing, set labels_test to -1
    if labels_test is None:
        labels_test = np.full(events_test.shape[0], 0, dtype=int)

    # Cast to cuda if available
    if torch.cuda.is_available():
        events_test   = events_test.to('cuda')
        context_test  = context_test.to('cuda')
        labels_test   = labels_test.to('cuda')

    ########################################################################
    #                         Using ContextBuilder                         #
    ########################################################################

    # Create ContextBuilder
    context_builder = ContextBuilder(
        input_size=62,
        output_size=62,
        hidden_size=512,
        max_length=10,
    )
    
    # Cast to CUDA if available
    if torch.cuda.is_available():
        context_builder = context_builder.to('cuda')

    # Train the ContextBuilder
    context_builder.fit(
        X=context_train,
        y=events_train.reshape(-1, 1),
        epochs=10,
        batch_size=128,
        learning_rate=0.02,
        verbose=True,
    )
    
    # Use context builder to predict confidence
    confidence, _ = context_builder.predict(
        X = context_test
    )
    # Get confidence of the next step, seq_len 0 (n_samples, seq_len, output_size)
    confidence = confidence[:, 0]
    # Get confidence from log confidence
    confidence = confidence.exp()
    # Get prediction as maximum confidence
    y_pred = confidence.argmax(dim=1)
    
    ########################################################################
    #                  Get prediction from ContextBuilder                  #
    ########################################################################

    '''
    # Get the total number of events in the test set
    total_events = context_test.shape[0]
    # Calculate the number of events per subset (divide by 5)
    events_per_subset = total_events // 5
    # Initialize lists to store the subsets
    context_subsets = []
    events_subsets = []
    labels_subsets = []

    # Loop through and split the test data into five subsets
    for i in range(5):
        start_index = i * events_per_subset
        end_index = (i + 1) * events_per_subset if i < 4 else total_events
        context_subset = context_test[start_index:end_index]
        events_subset = events_test[start_index:end_index]
        labels_subset = labels_test[start_index:end_index]
        context_subsets.append(context_subset)
        events_subsets.append(events_subset)
        labels_subsets.append(labels_subset)
    '''    
    ##############################################################################
    #                                 Comparison                                 #
    ##############################################################################
    
    # 讀取測試文件
    with open(test_prth, 'r') as file:
        data = file.readlines()

    cleaned_data = [item.strip() for item in data]

    # 使用列表推導式分隔每個字串，並將結果扁平化形成一個新的串列
    data = [item for sublist in cleaned_data for item in sublist.split()]

    #print("data:", data, "\nsize:", len(data))

    # 反轉 mapping，以便我們可以根據事件ID找到對應的編號
    reverse_mapping = {v: k for k, v in mapping_train.items()}

    # 轉換 events 列表中的每個字串為數字，然後根據 reverse_mapping 進行映射
    mapped_data = [reverse_mapping[int(event)] for event in data]

    #print("mapped_data:", mapped_data, "\nsize:", len(mapped_data))

    # 初始化一個零張量，用於存儲比較結果，長度與 test_normal_data 相同
    results = []

    # 遍歷 test_normal_data 的每一行
    for i in range(0, len(mapped_data)):
        match = False
        if mapped_data[i] == y_pred[i]:
            match = True
        
        # 如果有匹配，設置結果為0
        if match:
            results.append(0)
        else:
            results.append(1)

    print("results:", results, "\nsize:", len(results))

    # 計算列表中0的數量
    num_of_zero = results.count(0)
    print("虛警數量：%d" %num_of_zero )

    # 計算機率
    abnormal_rate = num_of_zero  / len(results)

    print("虛警率：%.4f" %abnormal_rate)
    
    # 文件路徑
    file_path = "/home/wang/project/allcomponents/DeepCASE/data/Wednesday-21-02-2018/Scount/source_ip_event_counts_DDOS-LOIC-UDP.txt"

    # 定義要保存的文件名
    output_file = "event_scores2.txt"
    # 初始化區間範圍
    bins = [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    # 初始化區間計數
    bin_counts = [0] * (len(bins) - 1)
    scores = []

    with open(output_file, 'w') as file_out:
        with open(file_path, 'r') as file:
            for line in file:
                ip, count = line.strip().split(':')
                count = int(count)
                ones_count = sum(results[:count])
                abnormal_score = ones_count / count * 100
                scores.append(abnormal_score)
                file_out.write(f"{ip} 的事件分數為 {abnormal_score}\n")

    # 計算每個區間的個數
    for score in scores:
        for i in range(len(bins) - 1):
            if bins[i] < score <= bins[i + 1]:
                bin_counts[i] += 1
                break

    # 繪製長條圖
    plt.figure(figsize=(10, 6))
    plt.bar(range(len(bin_counts)), bin_counts, width=0.8, color='skyblue', tick_label=[f"{bins[i]}-{bins[i+1]}" for i in range(len(bins)-1)])

    # 添加標題和標籤
    plt.title('Score Distribution')
    plt.xlabel('Score Range')
    plt.ylabel('Count')
    
    # 保存圖形到文件
    plt.savefig('score_distribution2.png')

    # 顯示長條圖
    plt.show()

    print(f"內容已保存到 {output_file}")
    
    # Get test and prediction as numpy array
    y_test = events_test.cpu().numpy()
    y_pred = y_pred     .cpu().numpy()

    # Print classification report
    print(classification_report(
        y_true = y_test,
        y_pred = y_pred,
        digits = 4,
    ))
    
    ########################################################################
    #                          Perform evaluation                          #
    ########################################################################
    '''
    # Initialize lists to store classification reports
    classification_reports = []

    for i in range(5):
        # Use context builder to predict confidence for the current subset
        confidence, _ = context_builder.predict(
            X = context_subsets[i]
        )
        # Get confidence of the next step, seq_len 0 (n_samples, seq_len, output_size)
        confidence = confidence[:, 0]
        # Get confidence from log confidence
        confidence = confidence.exp()
        # Get prediction as maximum confidence
        y_pred = confidence.argmax(dim=1)

        # Get test and prediction as numpy array
        y_test = events_subsets[i].cpu().numpy()
        y_pred = y_pred.cpu().numpy()

        # Generate classification report for the current subset
        report = classification_report(
            y_true = y_test,
            y_pred = y_pred,
            digits = 4,
            output_dict=True
        )
        classification_reports.append(report)

    ########################################################################
    #                      Aggregate classification reports                #
    ########################################################################

    # Compute average precision, recall, f1-score, support, accuracy, macro avg, and weighted avg
    aggregate_report = {}
    for label in classification_reports[0].keys():
        if label not in ['accuracy', 'macro avg', 'weighted avg']:
            metrics = ['precision', 'recall', 'f1-score', 'support']
            # Initialize lists to store metric values for the current label
            label_metrics = {metric: [] for metric in metrics}
            for report in classification_reports:
                # Check if the label exists in the current report
                if label in report:
                    for metric in metrics:
                        # Add metric value to the list if it exists, otherwise add 0
                        label_metrics[metric].append(report[label].get(metric, 0))
                else:
                    # If label does not exist in the report, add 0 to all metrics
                    for metric in metrics:
                        label_metrics[metric].append(0)
            # Compute mean of each metric for the current label
            aggregate_report[label] = {metric: np.mean(label_metrics[metric]) for metric in metrics}

    # Compute accuracy, macro avg, and weighted avg
    aggregate_report['accuracy'] = np.mean([report['accuracy'] for report in classification_reports])
    aggregate_report['macro avg'] = {metric: np.mean([aggregate_report[label][metric] for label in aggregate_report.keys() if label not in ['macro avg', 'weighted avg']]) for metric in metrics}
    aggregate_report['weighted avg'] = {metric: np.sum([aggregate_report[label]['support'] * aggregate_report[label][metric] for label in aggregate_report.keys() if label not in ['macro avg', 'weighted avg']]) / np.sum([aggregate_report[label]['support'] for label in aggregate_report.keys() if label not in ['macro avg', 'weighted avg']])}

    # Print aggregate classification report
    print("Aggregate Classification Report:")
    print(pd.DataFrame.from_dict(aggregate_report, orient='index'))
    '''
    
    ########################################################################
    #                          Using Interpreter                           #
    ########################################################################
    print(context_builder)
    # Create Interpreter
    interpreter = Interpreter(
        context_builder=context_builder,
        features=62,
        eps=0.2,
        min_samples=5,
        threshold=0.2,
    )

    # Cluster samples with the interpreter
    clusters = interpreter.cluster(
        X=context_train,
        y=events_train.reshape(-1, 1),
        iterations=150,
        batch_size=1024,
        verbose=True,
    )
    print(clusters)
    ########################################################################
    #                            Manual Mode                               #
    ########################################################################

    # Check if labels are valid for scoring
    NO_SCORE = -1
    if labels_train.size == 0 or np.all(labels_train == NO_SCORE):
        print("Warning: No valid labels for scoring.")
    else:
        scores = interpreter.score_clusters(
            scores=labels_train,
            strategy="max",
            NO_SCORE=NO_SCORE,
        )

        # Assign scores to clusters
        interpreter.score(
            scores=scores,
            verbose=True,
        )

    ########################################################################
    #                        (Semi-)Automatic mode                         #
    ########################################################################

    # Compute predicted scores
    prediction = interpreter.predict(
        X=context_test,
        y=events_test.reshape(-1, 1),
        iterations=150,
        batch_size=1024,
        verbose=True,
    )
    
    if not isinstance(prediction, pd.DataFrame):
        prediction_df = pd.DataFrame(prediction, columns=['Predicted_Label'])
    else:
        prediction_df = prediction

    # Save the DataFrame to a CSV file
    prediction_df.to_csv('prediction_results.csv', index=False)
    
    y_pred = prediction.cpu().numpy() if torch.is_tensor(prediction) else np.array(prediction)
    y_test = labels_test.cpu().numpy() if torch.is_tensor(labels_test) else np.array(labels_test)
    
    print(y_pred)
    print(y_test)
    
    print(classification_report(
    y_true=y_test,
    y_pred=y_pred,
    digits=4,
))