# Excluded uploaded CSV exports

Three uploaded files named `train-00000-of-00001-9564e8b05b4757ab...csv` are byte-equivalent in their 546 rows and labels. They each overlap with the selected multilingual test file (107 normalized texts), and 446 normalized texts overlap with the selected multilingual training file. Their split meaning is unclear, so they are intentionally not concatenated into training. This avoids triplicate weighting and accidental evaluation leakage.

Selected inputs:
- `raw/multilingual_train.csv`: 6,339 rows (`text`, `label`, `source`)
- `raw/multilingual_test.csv`: 1,585 rows (`text`, `label`, `source`)

The selected train and test files share 11 normalized text values. The training loader removes these overlapping training rows before making the internal stratified train/validation split. The test file remains unchanged for reporting.
