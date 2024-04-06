# event_id_extractor.py
import os
import json

class EventIDExtractor:
    def __init__(self, input_file_path, output_file):
        self.input_file_path = input_file_path
        self.output_file = output_file

    def extract_event_ids(self):
        file_names = sorted([f for f in os.listdir(self.input_file_path) if f.endswith('.json')])
        with open(self.output_file + ".txt", 'w', encoding='utf-8') as output_file:
            for file_name in file_names:
                file_path = os.path.join(self.input_file_path, file_name)
                with open(file_path, 'r', encoding='utf-8') as file:
                    data = json.load(file)
                    event_ids = [str(item['_source']['winlog']['event_id']) 
                                 for item in data['hits']['hits'] 
                                 if 'event_id' in item['_source']['winlog']]
                    output_file.write(' '.join(event_ids) + '\n')
        print(f'所有 Event IDs 已成功儲存到 "{self.output_file}"。')

    def clean_and_save(self):
        with open(self.output_file + ".txt", 'r', encoding='utf-8') as file:
            lines = file.readlines()
        cleaned_lines = [line for line in lines if line.strip() != '']
        with open(self.output_file, 'w', encoding='utf-8') as file:
            file.writelines(cleaned_lines)
        os.remove(self.output_file + ".txt")
        print(f'已整理檔案並儲存到 {self.output_file}')
