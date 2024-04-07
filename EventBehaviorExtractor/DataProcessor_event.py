import json
import pandas as pd
from pathlib import Path

class DataProcessor:
    def __init__(self, file_path, output_directories):
        self.file_path = Path(file_path)
        self.output_directories = {k: Path(v) for k, v in output_directories.items()}

    def extract_data(self):
        with open(self.file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
            records = [{
                'src_ip': item.get('src_ip', ''),
                'dest_ip': item.get('dest_ip', ''),
                'signature_id': str(item['alert'].get('signature_id', ''))
            } for item in data if 'alert' in item and 'signature_id' in item['alert']]
        self.df = pd.DataFrame(records)

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