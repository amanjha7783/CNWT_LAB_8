import dpkt
import socket
import sys
from collections import defaultdict, deque

def get_ip(raw_ip):
    if len(raw_ip) == 4:
        return socket.inet_ntop(socket.AF_INET, raw_ip)
    if len(raw_ip) == 16:
        return socket.inet_ntop(socket.AF_INET6, raw_ip)
    return ""

def get_record_type(record_type):
    types = {
        1: "A",
        2: "NS",
        5: "CNAME",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV"
    }
    return types.get(record_type, str(record_type))

def get_answer_value(answer):
    if answer.type == 1 and len(answer.rdata) == 4:
        return socket.inet_ntop(socket.AF_INET, answer.rdata)
    if answer.type == 28 and len(answer.rdata) == 16:
        return socket.inet_ntop(socket.AF_INET6, answer.rdata)
    if answer.type in (2, 5, 12):
        return answer.name
    return ""

def analyse_dns(filename):
    # Store queries until their matching responses arrive.
    pending = defaultdict(deque)
    results = []
    total_packets = 0
    dns_packets = 0
    query_count = 0
    response_count = 0
    response_times = []

    with open(filename, "rb") as file:
        capture = dpkt.pcap.Reader(file)

        for timestamp, raw_packet in capture:
            total_packets += 1

            try:
                ethernet = dpkt.ethernet.Ethernet(raw_packet)
                ip = ethernet.data

                if isinstance(ip, dpkt.ip.IP):
                    source_ip = get_ip(ip.src)
                    destination_ip = get_ip(ip.dst)
                elif isinstance(ip, dpkt.ip6.IP6):
                    source_ip = get_ip(ip.src)
                    destination_ip = get_ip(ip.dst)
                else:
                    continue

                udp = ip.data
                if not isinstance(udp, dpkt.udp.UDP):
                    continue

                if udp.sport != 53 and udp.dport != 53:
                    continue

                dns = dpkt.dns.DNS(udp.data)
                dns_packets += 1

                if dns.qd:
                    question = dns.qd[0]
                    domain = question.name.rstrip(".")
                    qtype = question.type
                else:
                    domain = "Unknown"
                    qtype = 0

                record_type = get_record_type(qtype)
                is_response = bool(dns.op & dpkt.dns.DNS_QR)

                if not is_response:
                    query_count += 1
                    key = (
                        source_ip, destination_ip,
                        udp.sport, udp.dport,
                        dns.id, domain.lower(), qtype
                    )
                    pending[key].append(timestamp)
                    continue

                response_count += 1
                key = (
                    destination_ip, source_ip,
                    udp.dport, udp.sport,
                    dns.id, domain.lower(), qtype
                )

                if pending[key]:
                    query_time = pending[key].popleft()
                    response_time = (timestamp - query_time) * 1000
                    response_times.append(response_time)
                    time_text = f"{response_time:.3f}"
                else:
                    time_text = "Not matched"

                returned_ips = []
                for answer in dns.an:
                    value = get_answer_value(answer)
                    if value:
                        returned_ips.append(value)

                if returned_ips:
                    ip_text = ", ".join(returned_ips)
                else:
                    ip_text = "No IP returned"

                results.append(
                    (domain, record_type, ip_text, time_text)
                )

            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError,
                    AttributeError, ValueError, TypeError):
                continue

    print("\nTotal Packets Scanned :", total_packets)
    print("Total DNS UDP Packets :", dns_packets)
    print("Total DNS Queries     :", query_count)
    print("Total DNS Responses   :", response_count)
    print("\nDNS QUERY / RESPONSE DETAILS")
    print("-" * 90)
    print(f"{'Domain':<38} {'Type':<8} {'Returned IP':<28} {'Response Time (ms)':>18}")
    print("-" * 90)

    for domain, record_type, ip_text, time_text in results:
        print(f"{domain:<38.38} {record_type:<8} {ip_text:<28.28} {time_text:>18}")

    print("-" * 90)
    print("\nDNS RESPONSE TIME ANALYSIS")

    if response_times:
        average_time = sum(response_times) / len(response_times)
        print(f"Matched Responses      : {len(response_times)}")
        print(f"Average Response Time  : {average_time:.3f} ms")
    else:
        print("No matching DNS query-response pairs were found.")

    print("\nAnalysis completed. Results are displayed in the terminal only.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyze_dns.py capture.pcap")
    else:
        try:
            analyse_dns(sys.argv[1])
        except FileNotFoundError:
            print("Error: Capture file not found. Check the file name and path.")
        except (ValueError, dpkt.dpkt.UnpackError) as error:
            print("Error reading capture file:", error)

