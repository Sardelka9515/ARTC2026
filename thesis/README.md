# 論文資料夾

本目錄存放「車聯網 Wi-Fi 資安測試平台」論文的撰寫素材。

## LaTeX 編譯與 PDF 預覽

正式主稿是 [main.tex](main.tex)，文獻資料放在 [references.bib](references.bib)。建議使用 XeLaTeX 編譯中文。

### 1. 安裝工具

在 macOS 以 Homebrew 安裝 MacTeX：

```bash
brew install --cask mactex-no-gui
```

安裝後重新開啟 VS Code 或終端機，確認：

```bash
xelatex --version
latexmk --version
```

### 2. 安裝 VS Code 擴充功能

在 Extensions 搜尋並安裝 **LaTeX Workshop**（識別碼：`James-Yu.latex-workshop`）。工作區已預先設定使用 XeLaTeX，輸出會放在 `thesis/build/`。

### 3. 在 VS Code 看 PDF

1. 開啟 `thesis/main.tex`。
2. 按 `Cmd+Option+B`，或從 Command Palette 執行 `LaTeX Workshop: Build LaTeX project`。
3. 編譯完成後，按 `Cmd+Option+V`，或執行 `LaTeX Workshop: View LaTeX PDF file`。
4. PDF 會在 VS Code 分頁中開啟；修改 `.tex` 後重新 Build 即可更新預覽。

也可在專案根目錄執行：

```bash
latexmk -xelatex -synctex=1 -interaction=nonstopmode -outdir=thesis/build thesis/main.tex
open thesis/build/main.pdf
```

目前環境尚未安裝 `xelatex` 與 `latexmk`，所以尚未產生 PDF；安裝上述工具後即可預覽。

## 使用方式

1. 先以 [論文架構.md](論文架構.md) 作為主稿，逐章補充實驗資料與引用。
2. 所有結果標記為「待補」的段落，應以真實測試紀錄、版本資訊或文獻取代。
3. 模擬資料只能用於說明開發流程，不可直接當作實體測試結果。
4. 每個實驗案例都應留下：測試日期、授權範圍、環境版本、輸入參數、原始日誌、結果與限制。

## 建議撰寫順序

1. 第三章：把現有系統與 API 整理成設計說明。
2. 第四章：補上實作細節與畫面截圖。
3. 第五章：建立實驗案例、指標與結果表。
4. 第一、二、六、七章：待系統與實驗穩定後完成敘事與分析。
5. 最後撰寫摘要、Abstract、結論與參考文獻。

## 論文證據最小集合

- 一張系統架構圖。
- 一張完整測試流程圖。
- 每個功能需求至少一個測試案例。
- 真實硬體與模擬模式的區分紀錄。
- 每項量化指標的原始資料與計算方式。
- 測試授權與隔離環境說明。