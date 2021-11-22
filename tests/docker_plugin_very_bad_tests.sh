python3 volatility3/vol.py -f memory_samples/dumpfile3.lime  -r pretty linux.docker --detector
python3 volatility3/vol.py -f memory_samples/dumpfile3.lime  -r pretty linux.docker --ps
python3 volatility3/vol.py -f memory_samples/dumpfile3.lime  -r pretty linux.docker --ps-extended
python3 volatility3/vol.py -f memory_samples/dumpfile3.lime  -r pretty linux.docker --inspect-caps
python3 volatility3/vol.py -f memory_samples/dumpfile3.lime  -r pretty linux.docker --inspect-mounts
python3 volatility3/vol.py -f memory_samples/dumpfile3.lime  -r pretty linux.docker --inspect-mounts-extended
python3 volatility3/vol.py -f memory_samples/dumpfile3.lime  -r pretty linux.docker --inspect-networks
python3 volatility3/vol.py -f memory_samples/dumpfile3.lime  -r pretty linux.docker --inspect-networks-extended