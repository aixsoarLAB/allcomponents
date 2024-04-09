## __0x00__ Hardware
- AWS EC2 c4.4xlarge, 100GB SSD, canonical `Ubuntu` 22.04 LTS (amd64, 3/3/2023).
- Tencent Cloud CVM, _with similar OS and hardware configurations_.

## __0x01__ Software
The demo can be built from a clean `Ubuntu` env.

```bash
# Establish env.
git clone https://github.com/fuchuanpu/HyperVision.git
cd HyperVision
sudo ./env/install_all.sh

# Download dataset.
wget [http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/CIC-IDS-2017/PCAPs/Friday-WorkingHours.md5](http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/CIC-IDS-2017/PCAPs/Friday-WorkingHours.pcap)

# Build and run HyperVision.
./script/rebuild.sh
./script/expand.sh
cd build && ../script/run_all_brute.sh && cd ..

# Analyze the results.
cd ./result_analyze
./batch_analyzer.py -g brute
cat ./log/brute/*.log | grep AU_ROC
cd -
```

