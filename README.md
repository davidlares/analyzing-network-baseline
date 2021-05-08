# Calculating the network baseline

Network baselining is the act of measuring and rating the performance of a network in a real-time situation.

The baseline requires testing and reporting of the overall network.

The `baseline.py` script calculates the network traffic profile of a known host based on a `pcap` file. Internally, the file performs a loop to each `Scapy` network object building a Python list, calculates the timestamp, and then gets to know the average and the ratio of the network session.

The two common indicators are the `average` and the `ratio`.

1. The `average` per second is the rate of the duration seconds divided by the total packets. If the average is higher than normal, this could indicate a sort of malicious network attack.

2. The `ratio` can be an indicator too. The ideal ratio value is that most packets generated must be part of a session if this value is sequentially decreased in profile sessions, which can be in presence of a DDoS attack

## Run

Simply run: `python baseline.py -i [IP] /path/to/[file].pcap -o output/[file].json`

You must run both pcap files. One for the `traffic.pcap` and other for the `attack.pcap`   

The `IP` argument must match or be present inside the `pcap` file. The example works well with the local IP `192.168.37.131`

## Output

Inside the `output` folder you will find both `.json` files for each `pcap` file analyzed.

You will see something like this

```
{
  "start_timestamp": 1579977788.159908,
  "end_timestamp": 1579978170.847968,
  "duration_secs": 382.68806,
  "total_packets": 233176,
  "total_sessions": 133920,
  "avg_pps": 0.0016411983222973205,
  "packets_to_sessions_ratio": 1.7411589008363202
}
```

# Baseline comparison

With the baselines from both experiences, you can compare the profiles, and based on your criteria, you can determine whether you are in presence of an anomaly or a malicious attempt. Sometimes an anomaly is not a malicious case. This will always depend on environmental situations and an analyst's criterial conception.

The `compare_profiles` uses both JSON files from the `output` directory, grab the average packet percentage and ratio (from both files), and calculates the upper and lower limit based on a threshold percent (set as CLI argument).

If by any means, the test profiles calculation exceeds the limits, it will be flagged

The output will show the upper and lower limits of the average and ratio for the network sessions and how it changes from both baselines

## Run code

The `-b` (baseline profile), the `-t` flag the profile to compare against, and the `threshold` is the difference between profiles and criteria to be flagged as an anomaly or malicious code

`python compare_network_profile.py -b /path/to/normal_profile.json -t /tmp/attack_profile.json -p 95`

## Output

Check how it looks:

```
[
  {
    "category": "Anomalous Packets per Second",
    "details": {
      "baseline_profile_avg_pps": 0.13988827913669064,
      "test_profile_avg_pps": 0.0016411983222973205,
      "baseline_profile_upper_limit": 0.27278214431654674,
      "baseline_profile_lower_limit": 0.006994413956834538,
      "baseline_profile_threshold_percent": 95.0
    }
  },
  {
    "category": "Anomalous Packets to Sessions Ratio",
    "details": {
      "baseline_profile_packets_sessions_ratio": 38.611111111111114,
      "test_profile_packets_sessions_ratio": 1.7411589008363202,
      "baseline_profile_upper_limit": 75.29166666666667,
      "baseline_profile_lower_limit": 1.9305555555555574,
      "baseline_profile_threshold_percent": 95.0
    }
  }
]
```

## Credits

 - [David E Lares](https://twitter.com/davidlares3)

## License

 - [MIT](https://opensource.org/licenses/MIT)
