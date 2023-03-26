import argparse
import pcapy
from scapy.all import *
import mysql.connector
from mysql.connector import Error

# Parse command line arguments
parser = argparse.ArgumentParser(description='Capture and analyze network traffic.')
parser.add_argument('--interface', type=str, default='eth0', help='the network interface to capture packets on')
parser.add_argument('--host', type=str, default='localhost', help='the MySQL server host')
parser.add_argument('--database', type=str, default='network_monitor', help='the name of the MySQL database')
parser.add_argument('--user', type=str, default='root', help='the MySQL database user')
parser.add_argument('--password', type=str, default='password', help='the MySQL database password')
args = parser.parse_args()

# Open the network interface and start capturing packets
cap = pcapy.open_live(args.interface, 65536, 1, 0)

# Connect to the MySQL server
try:
    connection = mysql.connector.connect(host=args.host,
                                         database=args.database,
                                         user=args.user,
                                         password=args.password)
    if connection.is_connected():
        print('Connected to MySQL database')

    # Create a table to store the packet data
    cursor = connection.cursor()
    create_table_query = '''CREATE TABLE packets
                            (id INT AUTO_INCREMENT PRIMARY KEY,
                             timestamp DATETIME NOT NULL,
                             src_ip VARCHAR(15) NOT NULL,
                             dst_ip VARCHAR(15) NOT NULL)'''
    cursor.execute(create_table_query)

    # Packet handler function for Scapy
    def packet_handler(pkt):
        # Add code here to analyze the packet data
        # Example: print the source and destination IP addresses
        print(f"Source IP: {pkt[IP].src}  Destination IP: {pkt[IP].dst}")

        # Insert the packet data into the database
        insert_query = "INSERT INTO packets (timestamp, src_ip, dst_ip) VALUES (%s, %s, %s)"
        cursor.execute(insert_query, (datetime.now(), pkt[IP].src, pkt[IP].dst))
        connection.commit()

    # Start capturing packets and call the packet handler for each captured packet
    while True:
        (header, data) = cap.next()
        pkt = Ether(data)
        packet_handler(pkt)

except Error as e:
    print('Error:', e)

finally:
    # Close the database connection
    cursor.close()
    connection.close()
