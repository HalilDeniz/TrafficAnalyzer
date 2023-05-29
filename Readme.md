# TrafficAnalyzer

TrafficAnalyzer is a powerful network traffic analysis tool that allows you to capture, analyze, and monitor network packets. It provides a user-friendly interface and a range of features for examining network traffic, detecting security threats, and generating statistical reports.

## Features

- Capture network packets and display detailed information about each packet, -
                  including source/destination IP addresses, ports, protocols, timestamps, packet size, and raw data.
- Save captured packets to a PCAP file for later analysis or sharing with others.
- Live monitoring mode for real-time packet capturing and analysis.
- Apply filters to capture specific types of packets based on protocols, IP addresses, ports, packet sizes, and more.
- Visualize captured packet statistics using charts and graphs. (Beta)
- Detect common security threats such as SQL injection, XSS (Cross-Site Scripting) attacks, and OS command injection.
- Maintain a list of active connections, including their source/destination IP addresses, ports, protocols, and timestamps.
- Make system more secure with firewall (Beta)
## Installation

1. Clone the repository:

   ```shell
   git clone https://github.com/HalilDeniz/TrafficAnalyzer.git
   ```

2. Install the required dependencies:

   ```shell
   pip install -r requirements.txt
   ```

## Usage

```shell
python trafficanalyzer.py [-h] [-i INTERFACE] [-f FILTER] [-c COUNT] [-sv] [-lm] [-tip TARGET_IP]
                           [-pr PROTOCOLS [PROTOCOLS ...]] [-tp TARGET_PORT] [--min MIN_PACKET_SIZE]
                           [--max MAX_PACKET_SIZE]
```

- `-h`, `--help`: Show the help message and usage instructions.
- `-i INTERFACE`, `--interface INTERFACE`: Specify the network interface to capture traffic (e.g., eth0, wlan0).
- `-f FILTER`, `--filter FILTER`: Set the filter expression for capturing packets (default: "tcp").
- `-c COUNT`, `--count COUNT`: Set the number of packets to capture (default: 10).
- `-sv`, `--save-packets`: Save captured packets to a PCAP file.
- `-lm`, `--live-monitor`: Enable live monitoring mode for real-time packet capturing and analysis.
- `-tip TARGET_IP`, `--target-ip TARGET_IP`: Set the destination IP address to capture packets.
- `-pr PROTOCOLS [PROTOCOLS ...]`, `--protocols PROTOCOLS [PROTOCOLS ...]`: Specify a list of protocols to filter packets.
- `-tp TARGET_PORT`, `--target-port TARGET_PORT`: Set the target port to capture packets.
- `--min MIN_PACKET_SIZE`: Set the minimum packet size for capturing.
- `--max MAX_PACKET_SIZE`: Set the maximum packet size for capturing.

## Examples

- Capture and analyze 100 TCP packets on the default network interface:

Tabii, işte boşaltılmış kullanım örnekleri:

- Capture and analyze packets on the default network interface:

  ```shell
  python trafficanalyzer.py
  ```

- Capture and save packets to a PCAP file:

  ```shell
  python trafficanalyzer.py -sv
  ```

- Capture packets with a specific filter expression:

  ```shell
  python trafficanalyzer.py -f "tcp and port 80"
  ```

- Capture packets to and from a specific IP address:

  ```shell
  python trafficanalyzer.py -tip 192.168.0.100
  ```

- Capture packets with specific protocols:

  ```shell
  python trafficanalyzer.py -pr tcp udp
  ```

- Capture packets with a specific target port:

  ```shell
  python trafficanalyzer.py -tp 8080
  ```

- Capture packets with a specific minimum packet size:

  ```shell
  python trafficanalyzer.py --min 100
  ```

- Capture packets with a specific maximum packet size:

  ```shell
  python trafficanalyzer.py --max 1500
  ```
  
  - Capture packets with a specific maximum and minimum packet size:

  ```shell
  python trafficanalyzer.py --min 150 --max 1500
  ```


## Contact

If you have any questions, comments, or suggestions about Tool Name, please feel free to contact me:

- LinkedIn: https://www.linkedin.com/in/halil-ibrahim-deniz/
- TryHackMe: https://tryhackme.com/p/halilovic
- Instagram: https://www.instagram.com/deniz.halil333/
- YouTube: https://www.youtube.com/c/HalilDeniz
- Email: halildeniz313@gmail.com

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
