from DataProcessor_event import DataProcessor


# 請確保您的文件路徑是正確的，這裡使用原始字串表示法
file_path =  r"D:\Users\admin\Desktop\data\Monday-WorkingHours\alerts_only.json"
output_directories = {
    'Ssid': r"D:\project\allcomponents\EventBehaviorExtractor\sequence\Ssid\source_ip_signatures.txt",
    'Dsid': r"D:\project\allcomponents\EventBehaviorExtractor\sequence\Dsid\destination_ip_signatures.txt",
    'Scount': r"D:\project\allcomponents\EventBehaviorExtractor\sequence\Scount\source_ip_event_counts.txt",
    'Dcount': r"D:\project\allcomponents\EventBehaviorExtractor\sequence\Dcount\destination_ip_event_counts.txt",
}

processor = DataProcessor(file_path, output_directories)
processor.run()