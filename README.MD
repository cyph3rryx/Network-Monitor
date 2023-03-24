# Network Monitoring Tool

This tool captures network traffic and stores the packet data in a MySQL database for later analysis. It uses the libpcap library to capture packets, the Scapy library to analyze packets, and the MySQL Connector/Python library to connect to the database.

## Requirements

    Python 3
    libpcap (for packet capture)
    Scapy (for packet analysis)
    MySQL (for packet storage)

## Installation

    1. Install Python 3 on your system.
    
    2. Install libpcap and Scapy using your system's package manager or by downloading the libraries from their respective websites.
    
    3. Install the MySQL Connector/Python library using pip:

pip install mysql-connector-python


## Usage

    1. Start the network monitoring tool by running the following command in the terminal:

python network_monitor.py

    2. The tool will start capturing packets on the default network interface (eth0). You can change the interface by modifying the cap variable in the network_monitor.py file.
    
    3. The packet data will be stored in a MySQL database named network_monitor. You can modify the database configuration by changing the host, database, user, and password variables in the network_monitor.py file.
    
    4. To stop the tool, press Ctrl+C in the terminal.

## License

This project is licensed under the MIT License - see the LICENSE.md file for details.

## Acknowledgments

    The libpcap, Scapy, and MySQL Connector/Python libraries for making this project possible.
