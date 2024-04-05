import pyshark
import pandas as pd
import numpy as np
from scipy.stats import norm
from scipy.stats import chi2_contingency
import matplotlib.pyplot as plt



src_ips = []
dst_ips = []
protocols = []

pcap_file = r"insert_path_location_here"

capture = pyshark.FileCapture(pcap_file)

for packet in capture:
    if 'IP' in packet:
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        protocol = packet.transport_layer
        src_ips.append(src_ip)
        dst_ips.append(dst_ip)
        protocols.append(protocol)
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}")

DataFrame = pd.DataFrame({"Source IP": src_ips, "Destination IP": dst_ips, "Protocol": protocols})

print(DataFrame.head())

source_ips = src_ips
dest_ips = dst_ips

source_ips_int = [int(ip.replace('.','')) for ip in source_ips]
dest_ips_int =  [int(ip.replace('.','')) for ip in dest_ips]

source_mean = np.mean(source_ips_int)
source_std_dev = np.std(source_ips_int)

dest_mean = np.mean(dest_ips_int)
dest_std_dev = np.std(dest_ips_int)

print("Destination IP Mean: ", dest_mean, "Source IP Mean: ", source_mean)

source_distribution = norm(source_mean, source_std_dev)
dest_distribution = norm(dest_mean, dest_std_dev)

# Sample observed frequencies for categories
observed_frequencies = [20, 30, 25, 15, 10]

# Sample expected frequencies for categories (normal distribution)
expected_frequencies = [20, 25, 30, 25, 20]

# Perform chi-square goodness of fit test
chi2_stat, p_val, _, _ = chi2_contingency([observed_frequencies, expected_frequencies])

# Output chi-square statistic and p-value
print("Chi-square statistic:", chi2_stat)
print("P-value:", p_val)

alpha = 0.05

if p_val < alpha:
    print("Observed distribution is significantly different from expected distribution. Potential anomaly detected")
    anomaly_detected = True
else:
    print("Observed distribution is not significantly different from expected distribution. No anomalies detected.")
    anomaly_detected = False

# Visualize observed and expected distributions
categories = ['L1', 'L2', 'L3', 'L4', 'L5']

plt.figure(figsize=(10, 6))

plt.bar(categories, observed_frequencies, color='blue', alpha=0.5, label='Observed')
plt.bar(categories, expected_frequencies, color='red', alpha=0.5, label='Expected')

plt.xlabel('Lists')
plt.ylabel('Frequency')
plt.title('Observed vs Expected Frequencies')
plt.legend()
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

# Generate report
if anomaly_detected:
    report = """
    Summary of Findings:
    --------------------
    Anomalies have been detected in the network traffic data based on the chi-square goodness of fit test.
    Potential Implications for Cybersecurity:
    - The detected anomalies may indicate abnormal patterns in the network traffic, which could be indicative of security breaches or malicious activities.
    - Further investigation is warranted to identify the root cause of the anomalies and assess their impact on the security posture of the network.
    Recommendations for Further Investigation or Mitigation:
    - Conduct a detailed analysis of the anomalous network traffic to understand the nature and scope of the anomalies.
    - Implement additional security measures such as intrusion detection systems or anomaly detection algorithms to enhance network security and mitigate potential risks.
    - Regularly monitor network traffic and update security protocols to adapt to evolving threats and vulnerabilities.
    """
else:
    report = """
    Summary of Findings:
    --------------------
    No anomalies have been detected in the network traffic data based on the chi-square goodness of fit test.
    The observed distribution is consistent with the expected distribution.
    """

print(report)

capture.close()
