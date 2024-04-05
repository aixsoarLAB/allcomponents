import os
import json

# 假設您的根目錄路徑是 root_path
root_path = '/home/ubuntu/ids2018-54-new'
output_file_path = 'ids2018-54.txt'

# 使用 with 語句和 'w' 模式打開檔案
with open(output_file_path, 'w', encoding='utf-8') as output_file:
    # 列出根目錄下的所有JSON檔案並排序
    file_names = sorted([file_name for file_name in os.listdir(root_path) if file_name.endswith('.json')])
    
    # 遍歷排序後的檔案名稱列表
    for file_name in file_names:
        file_path = os.path.join(root_path, file_name)
        
        # 使用 with 語句安全打開檔案
        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
            
            event_ids = []
            # 假設您的數據結構需要遍歷 'hits' -> 'hits' 列表
            for item in data['hits']['hits']:
                # 檢查是否存在 'event_id'，並抓取其值
                if 'event_id' in item['_source']['winlog']:
                    event_id = item['_source']['winlog']['event_id']
                    event_ids.append(str(event_id))
                    
            # 將所有的 event_id 寫入同一行，每個檔案的event_id占一行
            output_file.write(' '.join(event_ids) + '\n')

print(f'所有 Event IDs 已成功儲存到 "{output_file_path}"。')
