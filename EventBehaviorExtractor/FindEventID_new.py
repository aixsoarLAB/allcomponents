import os
import json

# 假設您的根目錄路徑是 root_path
root_path = '.\ids2018-54-new' 
output_file_path = 'ids2018-54'

# 使用 with 語句和 'w' 模式打開檔案
with open(output_file_path + ".txt", 'w', encoding='utf-8') as output_file:
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

os.rename(output_file_path + ".txt", output_file_path)

# 讀取檔案
file_name = 'ids2018-54'
file_path = './' + file_name  # 指定檔案路徑
with open(file_path, 'r', encoding='utf-8') as file:
    lines = file.readlines()

# 移除只包含換行符號的行
cleaned_lines = [line for line in lines if line.strip() != '']

# 將整理後的內容寫回到一個新檔案
cleaned_file_path = './' + file_name
with open(cleaned_file_path, 'w', encoding='utf-8') as file:
    file.writelines(cleaned_lines)

print(f'已整理檔案並儲存到 {cleaned_file_path}')
