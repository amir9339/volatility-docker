## volatility-docker (temporary name)

<br>

### ✨ Project Description

The objective of this project is to create a suite of plugins/parsers for [Volatility 3](https://github.com/volatilityfoundation/volatility3) for docker memory forensics.
We want to submit this project to Volatility Plugin Contest 2021

<br>

### 🎯 Goals for the Project

- Create a detection plugin that can detect the presence of docker containers in a memory sample based on processes lists, common structs, and FS artifacts.
- Create "docker like" commands that simulates docker common commands such as: 
    - `docker ps`
    - `docker diff`
    - `docker port`
    - `docker log`
    - And so on...
- Create detection plugins for common attacks / mis-configs

<br>

### ✔️ Prerequisites:

##### - Python 3 
##### - Volatility 3 as a python module

Install on linux (Debian) using these commands:

```bash
apt install python3
pip3 install volatility3
```

<br>

### ✍️ Contributers

- ##### [Ofek Shaked](https://github.com/oshaked1)
- ##### [Amir Sheffer](https://github.com/amir9339)
