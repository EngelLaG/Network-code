import matplotlib.pyplot as plt

# Collect the data
data_pdus = 1000
control_pdus = 500

# Calculate the ratio
ratio = data_pdus / control_pdus

# Visualize the data
routing_data_units = ['Data', 'Control', 'Routing A', 'Routing B']
ratios = [ratio, 1, 0.8, 1.2]

fig, ax = plt.subplots()
ax.bar(routing_data_units, ratios)
ax.set_ylabel('Ratio')
ax.set_title('Ratio of Routing Data Units')
plt.show()