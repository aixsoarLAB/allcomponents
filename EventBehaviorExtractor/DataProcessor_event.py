import os
import json
import pandas as pd
from pathlib import Path

class DataProcessor:
    # 初始化函式，設定檔案目錄和輸出目錄
    def __init__(self, file_directory, output_directories):
        self.file_directory = Path(file_directory)
        self.output_directories = {k: Path(v) for k, v in output_directories.items()}
        self.df = pd.DataFrame()

    # 從指定目錄提取數據
    def extract_data(self):
        # 檢查路徑是否指向目錄
        if not self.file_directory.is_dir():
            print(f"提供的路徑{self.file_directory}不是一個目錄")
            return
        
        # 遍歷目錄下的所有.json檔案
        for file_path in self.file_directory.glob('*.json'):
            with open(file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
                # 提取符合條件的數據並添加到紀錄中
                records = [{
                    'src_ip': item.get('src_ip', ''),
                    'dest_ip': item.get('dest_ip', ''),
                    'signature_id': str(item['alert'].get('signature_id', ''))
                } for item in data if 'alert' in item and 'signature_id' in item['alert']]
                # 將當前檔案的記錄追加到DataFrame中
                self.df = pd.concat([self.df, pd.DataFrame(records)], ignore_index=True)

    # 將數據寫入到檔案中
    def write_to_files(self):
        # 將每個 IP 的 signature_id 列表保存到檔案中
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

    # 執行數據提取和檔案寫入
    def run(self):
        self.extract_data()
        self.write_to_files()

class EventIDExtractor:
    # 提取事件ID並寫入檔案
    def extract_event_ids(input_file_path, output_file_path):
        file_names = sorted([f for f in os.listdir(input_file_path) if f.endswith('.json')])
        with open(output_file_path, 'w', encoding='utf-8') as output_file:
            for file_name in file_names:
                file_path = os.path.join(input_file_path, file_name)
                with open(file_path, 'r', encoding='utf-8') as file:
                    data = json.load(file)
                    # 提取事件ID並寫入檔案
                    event_ids = [str(item['_source']['winlog']['event_id']) 
                                 for item in data['hits']['hits'] 
                                 if 'event_id' in item['_source']['winlog']]
                    output_file.write(' '.join(event_ids) + '\n')
        print(f'所有 Event IDs 已成功儲存到 "{output_file_path}"。')

    # 提取Rule ID並寫入檔案
    def extract_rule_ids(input_file_path, output_file_path):
        with open(input_file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
            # 提取 rule 的 id 並寫入檔案
            event_ids = [str(item['_source']['rule']['id']) 
                         for item in data['hits']['hits'] 
                         if 'rule' in item['_source'] and 'id' in item['_source']['rule']]
        with open(output_file_path, 'w', encoding='utf-8') as output_file:
            output_file.write(' '.join(event_ids) + '\n')
        print(f'所有 Rule ID 已成功儲存到 "{output_file_path}"。')

    # 提取Security Event ID並寫入檔案
    def extract_SEIDS(input_file_path, output_file_path):
        with open(input_file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
            # 提取 rule 的 id 並寫入檔案
            event_ids = [str(item['_source']['id']) 
                         for item in data['hits']['hits'] 
                         if'id' in item['_source']]
        with open(output_file_path, 'w', encoding='utf-8') as output_file:
            output_file.write(' '.join(event_ids) + '\n')
        print(f'所有 Security Event ID 已成功儲存到 "{output_file_path}"。')

    # 刪除空白檔案(多個檔案轉換合併後包含空白適用)
    def clean_and_save(output_file_path):
        with open(output_file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        cleaned_lines = [line for line in lines if line.strip() != '']
        with open(output_file_path, 'w', encoding='utf-8') as file:
            file.writelines(cleaned_lines)
        print(f'已整理檔案並儲存到 {output_file_path}')

    # 刪除僅包含換行符號的檔案
    def delete_empty_file(output_file_path):
        with open(output_file_path, 'r', encoding='utf-8') as file:
            content = file.read().strip()
        
        if not content:
            os.remove(output_file_path)
            print(f'空白或僅包含換行符號的檔案 "{output_file_path}" 已被刪除。')
        else:
            print(f'檔案 "{output_file_path}" 不是空白的。')

    def merge_data(directory, output_file):
        # 獲取資料夾中的所有檔案名稱，並按名稱排序
        files = sorted([f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f)) and '.' not in f])
        
        with open(output_file, 'w', encoding='utf-8') as outfile:
            for filename in files:
                file_path = os.path.join(directory, filename)
                with open(file_path, 'r', encoding='utf-8') as infile:
                    content = infile.read()
                    outfile.write(content + '\n')
                # 刪除原始檔案
                os.remove(file_path)
                print(f'已刪除檔案: {file_path}')
        
        print(f'所有檔案已成功合併到 "{output_file}" 並刪除原始檔案。')