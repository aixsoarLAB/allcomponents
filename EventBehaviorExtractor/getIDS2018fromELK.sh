#!/bin/bash

# 定義單一索引名稱
index="ids-2018-172.31.64.54"

# 獲取索引末兩碼
indexSuffix=$(echo $index | grep -o '..$')

# 設定查詢開始和結束日期
startDate="2017-12-04"
endDate="2018-03-04"

# 轉換為秒，用於計算
startSec=$(date -d "$startDate" +%s)
endSec=$(date -d "$endDate" +%s)

# 每次增加的秒數（3小時）
increment=$((3 * 60 * 60))

# 從開始日期到結束日期循環
for (( currentSec=startSec; currentSec<endSec; currentSec+=increment )); do
    # 計算當前窗口的開始時間，並手動加上時區
    gte=$(date -d @"$currentSec" +%Y-%m-%dT%H:%M:%S)+08:00
    # 計算當前窗口的結束時間，並手動加上時區
    lte=$(date -d @"$((currentSec+increment-1))" +%Y-%m-%dT%H:%M:%S)+08:00
    
    # 獲取不包含時區的時間，用於檔案名稱
    gteForFile=$(date -d @"$currentSec" +%Y%m%d-%H)
    # 只取日期部分
    gteDate=$(echo $gteForFile | cut -d'-' -f1)
    # 只取小時部分
    gteHour=$(echo $gteForFile | cut -d'-' -f2)
    
    # 輸出檔案名稱，格式為ids2018-{index末兩碼}-{gteDate}-{gteHour}.json
    outputFile="ids2018-${indexSuffix}-${gteDate}-${gteHour}.json"

    # 執行查詢
    curl -X GET "http://localhost:9200/${index}/_search?pretty" -H 'Content-Type: application/json' -d'
    {
      "query": {
        "bool": {
          "filter": {
            "range": {
              "@timestamp": {
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