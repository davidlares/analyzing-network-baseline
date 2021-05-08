# Calculating the network baseline

Network baselining is the act of measuring and rating the performance of a network in a real-time situation.

The baseline requires testing and reporting of the overall network.

The `baseline.py` script calculates the network traffic profile of a known host based on a `pcap` file. Internally, the file performs a loop to each `Scapy` network object building a Python list, calculates the timestamp, and then gets to know the average and the ratio of the network session.

The two common indicators are the `average` and the `ratio`.

1. The `average` per second is the rate of the duration seconds divided by the total packets. If the average is higher than normal, this could indicate a sort of malicious network attack.

2. The `ratio` can be an indicator too. The ideal ratio value is that most packets generated must be part of a session if this value is sequentially decreased in profile sessions, which can be in presence of a DDoS attack

## Run

Simply run: `python baseline.py -i [IP] /path/to/[file].pcap`

The `IP` argument must match or be present inside the `pcap` file. The example works well with the local IP `192.168.37.131`

## Output

Inside the `output` folder you will find both `.json` files for each `pcap` file analyzed.

## Credits

 - [David E Lares](https://twitter.com/davidlares3)

## License

 - [MIT](https://opensource.org/licenses/MIT)
