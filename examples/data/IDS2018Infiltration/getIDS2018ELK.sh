#!/bin/bash

# 定義單一索引名稱
index="ids-2018-infiltration-13"
#index="ids-2018-infiltration-24"

# 獲取索引末兩碼
indexSuffix=$(echo $index | grep -o '...$')

# 設定查詢開始和結束日期
startDate="2018-03-01 09:57"
endDate="2018-03-01 10:55"

# 轉換為秒，用於計算
startSec=$(date -d "$startDate" +%s)
endSec=$(date -d "$endDate" +%s)

# 每次增加的秒數（半小時）
increment=$((30 * 60))

# 從開始日期到結束日期循環
for (( currentSec=startSec; currentSec<=endSec; currentSec+=increment )); do
    # 計算當前窗口的開始時間，並手動加上時區
    gte=$(date -d @"$currentSec" +%Y-%m-%dT%H:%M:%S)+08:00
    # 確保不超過結束時間
    nextSec=$((currentSec+increment))
    if [ $nextSec -gt $endSec ]; then
        nextSec=$endSec
    fi
    # 計算當前窗口的結束時間，並手動加上時區
    lte=$(date -d @"$nextSec" +%Y-%m-%dT%H:%M:%S)+08:00
    
    # 輸出檔案名稱，格式為ids2018-{index末兩碼}-{當前時間}.json
    outputFile="ids2018-${indexSuffix}-$(date -d @"$currentSec" +%Y%m%d-%H%M).json"

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