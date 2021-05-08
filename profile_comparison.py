import argparse
import json

# Anomaly vs Malicious

def compare_profiles(baseline_file, test_file, threshold=0.5):
    results = []
    # opening the first baseline file
    with open(baseline_file, 'r') as f:
        baseline_profile = json.load(f)

    # opening the test file (compare against)
    with open(test_file, 'r') as f:
        test_profile = json.load(f)

    # variables of the json files
    baseline_avg_pps = baseline_profile['avg_pps']
    baseline_packets_sessions_ratio = baseline_profile['packets_to_sessions_ratio']
    test_avg_pps = test_profile['avg_pps']
    test_packets_sessions_ratio = test_profile['packets_to_sessions_ratio']

    # limit calculations for the average of profiles
    baseline_avg_pps_upper_limit = baseline_avg_pps * (1 + threshold) # based on the % threshold
    baseline_avg_pps_lower_limit = baseline_avg_pps * (1 - threshold) # based on the % threshold

    # limit calculations limits for the ratio of profiles
    baseline_packets_sessions_upper_limit = baseline_packets_sessions_ratio * (1 + threshold) # based on the % threshold
    baseline_packets_sessions_lower_limit = baseline_packets_sessions_ratio * (1 - threshold) # based on the % threshold

    # comparison
    if test_avg_pps > baseline_avg_pps_upper_limit or test_avg_pps < baseline_avg_pps_lower_limit:
        result = {'category': 'Anomalous Packets per Second',
                  'details': {'baseline_profile_avg_pps': baseline_avg_pps, 'test_profile_avg_pps': test_avg_pps,
                              'baseline_profile_upper_limit': baseline_avg_pps_upper_limit,
                              'baseline_profile_lower_limit': baseline_avg_pps_lower_limit,
                              'baseline_profile_threshold_percent': threshold * 100}}
        # writing results as json
        results.append(result)

    if test_packets_sessions_ratio > baseline_packets_sessions_upper_limit or test_packets_sessions_ratio < baseline_packets_sessions_lower_limit:
        result = {'category': 'Anomalous Packets to Sessions Ratio',
                  'details': {'baseline_profile_packets_sessions_ratio': baseline_packets_sessions_ratio,
                              'test_profile_packets_sessions_ratio': test_packets_sessions_ratio,
                              'baseline_profile_upper_limit': baseline_packets_sessions_upper_limit,
                              'baseline_profile_lower_limit': baseline_packets_sessions_lower_limit,
                              'baseline_profile_threshold_percent': threshold * 100}}
         # writing results as json
        results.append(result)
    return results

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='This application compares a baseline network traffic profile against another profile to look for malicious/anomalous activity.')
    parser.add_argument('-b', '--baseline', required=True, help='File containing baseline profile (JSON format) to read from')
    parser.add_argument('-t', '--test-file', required=True, help='File containing test profile (JSON format) to read from')
    parser.add_argument('-p', '--percent-threshold', default=50, help='Percent difference test profile must be from baseline profile to be considered malicious/anomalous')
    parser.add_argument('-o', '--output', help='Output file to write to')
    args = parser.parse_args()

    # handling arg parameters
    baseline_file = args.baseline
    test_file = args.test_file
    threshold = int(args.percent_threshold) / 100
    output = args.output

    # performing analysis with both test files and the
    analysis = compare_profiles(baseline_file, test_file, threshold)

    # output the results
    if output:
        with open(output, 'w') as of:
            json.dump(analysis, of, indent=2)
    else:
        print(json.dumps(analysis, indent=2))
