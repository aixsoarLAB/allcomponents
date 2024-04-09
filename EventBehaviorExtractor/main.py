from DataProcessor_event import DataProcessor
from DataProcessor_event import EventIDExtractor


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

input_file_path = 'ids2018-54-new'
output_file_path = 'sequence/ids2018-54'
extractor = EventIDExtractor(input_file_path, output_file_path)
extractor.extract_event_ids()
extractor.clean_and_save()