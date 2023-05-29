import sqlite3

class DatabaseManager:
    def __init__(self, db_name):
        self.db_name = db_name
        self.conn = None
        self.cursor = None

    def connect(self):
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()

        self.cursor.execute('''DROP TABLE IF EXISTS packets''')

        self.cursor.execute('''CREATE TABLE packets (
                                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                                    src_ip TEXT,
                                    dst_ip TEXT,
                                    src_port INTEGER,
                                    dst_port INTEGER,
                                    protocol INTEGER,
                                    timestamp REAL,
                                    packet_size INTEGER,
                                    raw_data BLOB,
                                    src_mac TEXT,
                                    dst_mac TEXT
                                )''')

    def save_packet(self, packet_info):
        query = '''INSERT INTO packets (
                        src_ip, dst_ip, src_port, dst_port, protocol, timestamp, packet_size, raw_data, src_mac, dst_mac
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'''
        values = (
            packet_info['src_ip'],
            packet_info['dst_ip'],
            packet_info['src_port'],
            packet_info['dst_port'],
            packet_info['protocol'],
            packet_info['timestamp'],
            packet_info['packet_size'],
            packet_info['raw_data'],
            packet_info['src_mac'],
            packet_info['dst_mac']
        )
        self.cursor.execute(query, values)
        self.conn.commit()

    def close(self):
        self.cursor.close()
        self.conn.close()
