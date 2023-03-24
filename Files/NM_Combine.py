import pcapy
from scapy.all import *
import mysql.connector
from mysql.connector import Error

# Open the network interface and start capturing packets
cap = pcapy.open_live('eth0', 65536, 1, 0)

# Connect to the MySQL server
try:
    connection = mysql.connector.connect(host='localhost',
                                         database='network_monitor',
                                         user='root',
                                         password='password')
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
