import os
from DataProcessor_event import DataProcessor
from DataProcessor_event import EventIDExtractor

def get_json_filefolder(directory):
    # 創建一個空串列來存儲JSON檔案名稱
    json_files = []

    # 遍歷資料夾中的所有文件
    for filename in os.listdir(directory):
        # 檢查文件是否為JSON檔案
        if filename.endswith('.json'):
            json_files.append(directory + "/" + filename)
    
    json_files.sort()

    return json_files

#########################
#       SID 使用        # 
#########################
'''
# 請確保您的文件路徑是正確的，這裡使用原始字串表示法
file_path =  'events/Monday'
output_directories = {
    'Ssid': r"D:\project\allcomponents\EventBehaviorExtractor\sequence\Ssid\source_ip_signatures.txt",
    'Dsid': r"D:\project\allcomponents\EventBehaviorExtractor\sequence\Dsid\destination_ip_signatures.txt",
    'Scount': r"D:\project\allcomponents\EventBehaviorExtractor\sequence\Scount\source_ip_event_counts.txt",
    'Dcount': r"D:\project\allcomponents\EventBehaviorExtractor\sequence\Dcount\destination_ip_event_counts.txt",
}

processor = DataProcessor(file_path, output_directories)
processor.run()
'''

#########################
#   Event/rule ID 使用  #
#########################

filefolder_path = "../data/wazuh-20240519"
input_file_path = get_json_filefolder(filefolder_path) 
head, sep, tail = filefolder_path.rpartition('/')
foldername = tail
output_file_path = '../data/convertData/'+ foldername

for i in range(len(input_file_path)):
    head, sep, tail = input_file_path[i].rpartition('/')
    filename = tail[:-5]

    outputFileName = output_file_path + "-" + filename + "-ruleID"
    EventIDExtractor.extract_rule_ids(input_file_path[i], outputFileName)
    EventIDExtractor.delete_empty_file(outputFileName)

    outputFileName = output_file_path + "-" + filename + "-SEID"
    EventIDExtractor.extract_SEIDS(input_file_path[i], outputFileName)
    EventIDExtractor.delete_empty_file(outputFileName)

#########################
#   Training data 使用  # 
#########################
'''
filefolder_path = "../data/wazuh-trainingData"
input_file_path = get_json_filefolder(filefolder_path) 
head, sep, tail = filefolder_path.rpartition('/')
foldername = tail
output_file_path = '../data/convertDataTraining/'+ foldername

for i in range(len(input_file_path)):
    head, sep, tail = input_file_path[i].rpartition('/')
    filename = tail[:-5]

    outputFileName = output_file_path + "-" + filename + "-ruleID"
    EventIDExtractor.extract_rule_ids(input_file_path[i], outputFileName)
    EventIDExtractor.delete_empty_file(outputFileName)

filefolder_path = "../data/convertDataTraining"
output_file_path = '../data/convertDataTraining/' + "wazuh_training_data"
EventIDExtractor.merge_data(filefolder_path, output_file_path)
EventIDExtractor.clean_and_save(output_file_path)
'''