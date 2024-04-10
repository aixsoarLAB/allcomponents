# 開發環境與執行步驟指南

## 前提條件:

- 確保已在電腦上安裝 Git。
- 確保已在電腦上安裝 Visual Studio Code (VSCode)。
- 確保已在電腦上安裝 Python 。

## 從 GitHub 克隆專案
1. 打開終端機或命令提示符。
2. 導航到希望保存專案的目錄。
3. 使用以下命令克隆專案：

`git clone -b bojsa --single-branch git@github.com:aixsoarLAB/allcomponents.git`


4. 進入克隆下來的專案目錄：

`cd NetworkGraph`

## 使用 VSCode 打開專案
1. 啟動 VSCode。
2. 在文件菜單中選擇「Open Folder」，然後選擇您克隆的專案目錄。

## 設定 Python 環境
1. 在 VSCode 中，打開一個 .ipynb 文件。
2. 如果尚未安裝 Python 擴充功能，VSCode 將提示您安裝。請按照提示安裝。
3. 在 VSCode 底部的狀態欄上，選擇 Python 解釋器。

## 安裝必要的 Python 包
1. 打開 VSCode 的終端機視窗。
2. 確保您正處於專案目錄下，然後運行以下命令來安裝所需的 Python 包

`pip install -r requirements.txt`

## 執行 .ipynb 檔案
1. 在 VSCode 中打開 NetworkGraph_modularize_testing.ipynb 文件。
2. 您可以逐一執行每個單元格，或使用頂部的「Run All」按鈕執行所有單元格。
