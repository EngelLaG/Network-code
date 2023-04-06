import random
import matplotlib.pyplot as plt

# Define the list of PDUs
pdus = ["STP", "DTP", "CDP", "ARP", "ICMP", "DNS", "DHCP"]

# Generate a random sample of PDUs
sample_size = 500
pdus = [random.choice(pdus + ["Data"]) for i in range(sample_size)]

# Count the number of control and data PDUs
c_count = pdus.count("Data")
data_count = sample_size - c_count

# Print the data and  PDUs
print("Data PDUs:", pdus.count("Data"))
for pdu in pdus:
    print(pdu, "PDUs:", pdus.count(pdu))

# Calculate the ratio of data to PDUs
ratio = data_count / c_count

# Plot the ratio as a bar chart
plt.bar(["Data", "Control"], [data_count, c_count])
plt.title("Ratio of Data to Control PDUs")
plt.xlabel("PDUs")
plt.ylabel("Count")
print("Close the chart to get the ratio")
plt.show()

print("Ratio of Data to Control PDUs: {:.2f}".format(ratio))