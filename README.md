## volatility-docker (temporary name)
<br />

[![DeepSource](https://deepsource.io/gh/amir9339/volatility-docker.svg/?label=active+issues&show_trend=true&token=rispzL5PcBGqIqQ6VWX2FWRL)](https://deepsource.io/gh/amir9339/volatility-docker/?ref=repository-badge)
<br />

### ✨ Project Description

The objective of this project is to create a suite of [Volatility 3](https://github.com/volatilityfoundation/volatility3) plugins for memory forensics of Docker, Linux namespaces and other container related aspects.
We want to submit this project to the 2021 Volatility Plugin Contest.

### 🎯 Goals for the Project

- Create plugins that are equivalent to the Volatility 2 plugins `mount`, `find_file` and `ifconfig`, while being completely aware of Linux namespaces (these plugins are needed for the other ones that are planned).

- Create a plugin that can detect the presence of Docker containers based on processes, network interfaces, and FS artifacts.
- Create a Docker command plugin that emulates common Docker commands such as:
    - `docker ps`
    - `docker network ls`
    - `docker images`
    - `docker diff`
    - `docker save`
    - `docker port`
    - `docker logs`
    - And more...
- Create a plugin that detects common attacks / misconfigurations of Docker containers.

### ✔️ Prerequisites:

##### - Python 3
##### - Volatility 3

Install on Linux (Debian) using these commands:

```bash
apt install python3

# clone from repo
git clone https://github.com/volatilityfoundation/volatility3.git

# or install as a module
pip3 install volatility3
```

### ⚙ Installation

All plugins are located in the `plugins` folder. Copy them to your Volatility 3 directory under `volatility3/volatility3/framework/plugins/linux`.

Some other framework extensions are required. They are located under `volatility3 changes`, and are organized in the same directory structure as their location within Volatility 3. Simply copy them to the same location (overwrite existing files if needed).

### ✍️ Contributors

- ##### [Ofek Shaked](https://github.com/oshaked1)
- ##### [Amir Sheffer](https://github.com/amir9339)
