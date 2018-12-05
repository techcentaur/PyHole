# PyHole
A Python wrapper for Pi-hole.

#### What is Pi-Hole
The Pi-hole® is a DNS sinkhole that protects your devices from unwanted content, without installing any client-side software. Find more about it [here](https://github.com/pi-hole/pi-hole).


## Configuration

Edit the `config.yml` file as
```
IP_address: <your_ip_here>
password: <password>
```

## Object Instance

```python3
from pihole import PyHole
ph = PyHole()  # create an instance
ph.authenticate() # authenticate pihole

ph.enable_pihole() # enable pihole
ph.get_list("black") # get the blocked list
```
