import unittest
import random
import matplotlib.pyplot as plt

class TestPduCounter(unittest.TestCase):

    def test_pdu_count(self):
        # Define the list of PDUs
        pdus = ["STP", "DTP", "CDP", "ARP", "ICMP", "DNS", "DHCP"]

        # Generate a random sample of PDUs
        sample_size = 500
        pdus = [random.choice(pdus + ["Data"]) for i in range(sample_size)]

        # Count the number of control and data PDUs
        c_count = pdus.count("Data")
        data_count = sample_size - c_count

        # Check if the counts are correct
        self.assertEqual(pdus.count("Data"), data_count)
        for pdu in pdus:
            self.assertEqual(pdus.count(pdu), pdus.count(pdu))

    def test_pdu_ratio(self):
        # Define the list of PDUs
        pdus = ["STP", "DTP", "CDP", "ARP", "ICMP", "DNS", "DHCP"]

        # Generate a random sample of PDUs
        sample_size = 500
        pdus = [random.choice(pdus + ["Data"]) for i in range(sample_size)]

        # Count the number of control and data PDUs
        c_count = pdus.count("Data")
        data_count = sample_size - c_count

        # Calculate the ratio of data to PDUs
        ratio = data_count / c_count

        # Check if the ratio is correct
        self.assertAlmostEqual(ratio, data_count/c_count)

    def test_plot(self):
        # Define the list of PDUs
        pdus = ["STP", "DTP", "CDP", "ARP", "ICMP", "DNS", "DHCP"]

        # Generate a random sample of PDUs
        sample_size = 500
        pdus = [random.choice(pdus + ["Data"]) for i in range(sample_size)]

        # Count the number of control and data PDUs
        c_count = pdus.count("Data")
        data_count = sample_size - c_count

        # Calculate the ratio of data to PDUs
        ratio = data_count / c_count

        # Plot the ratio as a bar chart
        plt.bar(["Data", "Control"], [data_count, c_count])
        plt.title("Ratio of Data to Control PDUs")
        plt.xlabel("PDUs")
        plt.ylabel("Count")

        # Check if the plot was created successfully
        self.assertIsNotNone(plt.gcf())

if __name__ == '__main__':
    unittest.main()
