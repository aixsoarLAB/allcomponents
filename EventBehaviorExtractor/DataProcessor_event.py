import os
import json
import pandas as pd
from pathlib import Path

class DataProcessor:
    def __init__(self, file_directory, output_directories):
        self.file_directory = Path(file_directory)
        self.output_directories = {k: Path(v) for k, v in output_directories.items()}
        self.df = pd.DataFrame()

    def extract_data(self):
        # 检查路径是否指向目录
        if not self.file_directory.is_dir():
            print(f"提供的路径{self.file_directory}不是一个目录")
            return
        
        # 遍历目录下的所有.json文件
        for file_path in self.file_directory.glob('*.json'):
            with open(file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
                records = [{
                    'src_ip': item.get('src_ip', ''),
                    'dest_ip': item.get('dest_ip', ''),
                    'signature_id': str(item['alert'].get('signature_id', ''))
                } for item in data if 'alert' in item and 'signature_id' in item['alert']]
                # 将当前文件的记录追加到DataFrame中
                self.df = pd.concat([self.df, pd.DataFrame(records)], ignore_index=True)

    def write_to_files(self):
        # 將每個 IP 的 signature_id 列表保存到文件中
        for column, file_name in [('src_ip', 'Ssid'), ('dest_ip', 'Dsid')]:
            grouped_signatures = self.df.groupby(column)['signature_id'].apply(lambda x: ' '.join(x)).sort_index()
            output_file = self.output_directories[file_name]
            with output_file.open('w', encoding='utf-8') as file:
                for signatures in grouped_signatures:
                    file.write(f"{signatures}\n")
        
        # 計算每個 IP 觸發事件的次數
        for column, file_name in [('src_ip', 'Scount'), ('dest_ip', 'Dcount')]:
            counts = self.df[column].value_counts().sort_index().reset_index()
            counts.columns = [column, 'count']
            output_file = self.output_directories[file_name]
            counts.to_csv(output_file, index=False, header=False, sep=":")

    def run(self):
        self.extract_data()
        self.write_to_files()

class EventIDExtractor:
    def __init__(self, input_file_path, output_file):
        self.input_file_path = input_file_path
        self.output_file = output_file

    def extract_event_ids(self):
        file_names = sorted([f for f in os.listdir(self.input_file_path) if f.endswith('.json')])
        with open(self.output_file, 'w', encoding='utf-8') as output_file:
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
        with open(self.output_file, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        cleaned_lines = [line for line in lines if line.strip() != '']
        with open(self.output_file, 'w', encoding='utf-8') as file:
            file.writelines(cleaned_lines)
        print(f'已整理檔案並儲存到 {self.output_file}')