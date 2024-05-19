#!/bin/bash

# 定義單一索引名稱
index="wazuh-alerts-*"

# 設定查詢開始和結束日期
startDate="2024-05-14 21:00:00"
endDate="2024-05-19 20:59:59"

# 轉換為秒，用於計算
startSec=$(date -d "$startDate" +%s)
endSec=$(date -d "$endDate" +%s)

# 每次增加的秒數（1小時）
increment=$((3 * 60 * 60))

# 從開始日期到結束日期循環
for (( currentSec=startSec; currentSec<endSec; currentSec+=increment )); do
    # 計算當前窗口的開始時間，並手動加上時區
    gte=$(date -d @"$currentSec" +%Y-%m-%dT%H:%M:%S)+08:00
    # 計算當前窗口的結束時間，並手動加上時區
    lte=$(date -d @"$((currentSec+increment-1))" +%Y-%m-%dT%H:%M:%S)+08:00
    
    # 輸出檔案名稱，格式為wazuh-{開始日期}.json
    outputFile="wazuh-${gte}.json"

    # 執行查詢
    curl -u admin:D3bjCYTI4dO.n5yaOzUQmEpH33QRV4sz -k -X GET "https://127.0.0.1:9200/${index}/_search?pretty" -H 'Content-Type: application/json' -d'
    {
      "query": {
        "bool": {
          "filter": {
            "range": {
              "timestamp": {
                "gte": "'"$gte"'",
                "lte": "'"$lte"'"
              }
            }
          }
        }
      },
      "size": 10000
    }' > "$outputFile"
done
