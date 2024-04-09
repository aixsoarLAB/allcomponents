
The README instructions you've provided are clear but can be slightly modified for better clarity and adherence to best practices. Below are some suggested modifications:

Operating System:
Ubuntu 22.04 LTS

Setting up the Environment:
First, clone the HyperVision repository and set up the necessary environment by running the following commands in your terminal:

```bash
git clone https://github.com/fuchuanpu/HyperVision.git
cd HyperVision
sudo ./env/install_all.sh
```
Downloading the Dataset:
Download the dataset required for HyperVision using wget:
```bash
wget http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/CIC-IDS-2017/PCAPs/Friday-WorkingHours.pcap
```
Building and Running HyperVision:
Build HyperVision and run the provided scripts as follows:
```bash
./script/rebuild.sh
./script/expand.sh
cd build
set -eux
ninja
```
Running the HyperVision Module:
Finally, execute HyperVision with the following command:
```bash
./HyperVision
```

