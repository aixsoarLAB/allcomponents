# main.py
from event_id_extractor import EventIDExtractor

# 使用範例
input_file_path = 'ids2018-54-new'
output_file_path = 'ids2018-54'
extractor = EventIDExtractor(input_file_path, output_file_path)
extractor.extract_event_ids()
extractor.clean_and_save()