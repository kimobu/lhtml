# Learning How to Machine Learn

This project contains files to practice machine learning with Mach-O files.

### Data
There are about 1,000 malicious Mach-O files that were downloaded from various sites. There's also about 1,000 benign Mach-O files. Both sets of data were packed with UPX. All those files were parsed with [macholibre](https://github.com/aaronst/macholibre) and the output was stored in `benign_data` and `malware_data`. An additional 300 malicious Mach-Os are available in `validation_data`.

### Models
`randomforest_macho.ipynb` contains an end-to-end walkthrough of loading the data, feature engineering, hyper parameter optimization, and performance assessment.