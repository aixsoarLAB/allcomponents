from DataProcessor_event import DataProcessor
from DataProcessor_event import EventIDExtractor

#########################
#      SID 使用         # 
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
#     EventID 使用      # 
#########################

input_file_path = ['../examples/data/IDS2018Bot', 
                   '../examples/data/IDS2018Infiltration', 
                   '../examples/data/IDS2018Benign-test',
                   '../examples/data/IDS2018Benign'] 
output_file_path = ['../examples/data/IDS2018_test_abnormal_Bot', 
                    '../examples/data/IDS2018_test_abnormal_Infiltration', 
                    '../examples/data/IDS2018_test_Benign',
                    '../examples/data/IDS2018_train_Benign']

for i in range(len(input_file_path)):
    extractor = EventIDExtractor(input_file_path[i], output_file_path[i])
    extractor.extract_event_ids()
    extractor.clean_and_save()