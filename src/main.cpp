#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <pcap/pcap.h>

// Output file names.
constexpr std::string_view DST_IPS_OUPUT_FILENAME = "dst_ip_analysis.txt";
constexpr std::string_view PROTO_OUPUT_FILENAME = "proto_analysis.txt";

/**
 * @brief PcapData struct used to store specific information related to a pcap.
 */
struct PcapData
{
    // Track the total number of packets analysed.
    u_int32_t num_packets = 0;
    // Track the total size of packets analysed.
    u_int32_t total_packet_size = 0;
    // Track the total volume of data analysed.
    // Data is equal to packet size - (eth header, ip header and tcp/udp header).
    u_int32_t total_data_volume = 0;
    // Map to track different destination IPs and their respective packet count.
    std::unordered_map<std::string, u_int32_t> dst_ip_frequency_map =
        std::unordered_map<std::string, u_int32_t>{};
    // Map to track different transport protocols and their respective packet count.
    std::unordered_map<u_int16_t, u_int32_t> transport_proto_frequency_map =
        std::unordered_map<u_int16_t, u_int32_t>{};
};

/** @brief Check whether integer overflow would occur if two unsigned integers were added together.
 *
 * @param[in]  a  The first integer.
 * @param[in]  b  The second integer.
 * @return Returns true when an overflow would occur, else false.
 */
bool is_addition_overflow(u_int32_t a, u_int32_t b)
{
    return b > std::numeric_limits<u_int32_t>::max() - a;
}

/** @brief Safely add two unsigned integers together. Exit the program if an overflow would occur.
 *
 * @param[in]  a  The first integer.
 * @param[in]  b  The second integer.
 * @return Returns the sum if an overflow did not occur.
 */
u_int32_t safe_add(u_int32_t a, u_int32_t b)
{
    if (is_addition_overflow(a, b))
    {
        std::cout << "Unsigned integer overflow detected. Exiting." << "\n";
        std::exit(-1);
    }
    return a + b;
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    auto *pcap_data = reinterpret_cast<PcapData *>(user_data);

    // Increment the number of packets processed.
    pcap_data->num_packets = safe_add(pcap_data->num_packets, 1);

    // Use len rather than caplen to ensure we record the actual size of the
    // packet not the size that was captured.
    pcap_data->total_packet_size = safe_add(pcap_data->total_packet_size, pkthdr->len);

    auto eth_header = reinterpret_cast<const struct ether_header *>(packet);
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP)
    {
        auto dst_ip_buf = std::array<char, INET_ADDRSTRLEN>{};
        auto ip_header = reinterpret_cast<const struct ip *>(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_buf.data(), INET_ADDRSTRLEN);

        // Increment the number of times we've seen this destination IP.
        const auto dst_ip = std::string(dst_ip_buf.data());
        pcap_data->dst_ip_frequency_map[dst_ip] = safe_add(pcap_data->dst_ip_frequency_map[dst_ip], 1);

        // Increment the number of times we've seen this transport layer
        // protocol.
        pcap_data->dst_ip_frequency_map[dst_ip] = safe_add(pcap_data->transport_proto_frequency_map[ip_header->ip_p], 1);

        // Determine the size of the data sent in the packet depending on if it
        // was TCP or UDP.
        if (ip_header->ip_p == IPPROTO_TCP)
        {
            auto data_size = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) +
                                            sizeof(struct tcphdr));
            pcap_data->total_data_volume = safe_add(pcap_data->total_data_volume, data_size);
        }
        else if (ip_header->ip_p == IPPROTO_UDP)
        {
            auto data_size = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) +
                                            sizeof(struct udphdr));
            pcap_data->total_data_volume = safe_add(pcap_data->total_data_volume, data_size);
        }
    }
}

int main()
{
    auto pcap_error_buf = std::array<char, PCAP_ERRBUF_SIZE>{};
    pcap_t *pcap_handle = pcap_open_offline("packet-storm.pcap", pcap_error_buf.data());
    if (nullptr == pcap_handle)
    {
        std::cout << pcap_error_buf.data() << "\n";
        return -1;
    }

    PcapData pcap_analyzer = PcapData();

    if (pcap_loop(pcap_handle, 0, packet_handler, reinterpret_cast<u_char *>(&pcap_analyzer)))
    {
        std::cout << pcap_geterr(pcap_handle) << "\n";
        return -1;
    }

    // Convert dst IPs from unordered map to vector to be able to sort.
    auto sorted_dst_ips = std::vector<std::pair<std::string, u_int32_t>>(
        pcap_analyzer.dst_ip_frequency_map.begin(), pcap_analyzer.dst_ip_frequency_map.end());
    std::sort(sorted_dst_ips.begin(), sorted_dst_ips.end(),
              [](auto &left, auto &right)
              { return left.second > right.second; });
    auto avg_packet_size = pcap_analyzer.total_packet_size / pcap_analyzer.num_packets;

    std::cout << "Average packet size: " << avg_packet_size << " B" << "\n";
    std::cout << "Total volume of data: " << pcap_analyzer.total_data_volume << " B\n";
    std::cout << "Total unique destination IPs: " << sorted_dst_ips.size() << "\n";

    // Write analysis to files for easier readability.
    std::ofstream dst_ips_stream(DST_IPS_OUPUT_FILENAME);
    for (const auto &[dst_ip, freq] : sorted_dst_ips)
    {
        dst_ips_stream << dst_ip << " = " << freq << "\n";
    }
    dst_ips_stream.close();

    std::ofstream proto_stream(PROTO_OUPUT_FILENAME);
    for (const auto &[proto, freq] : pcap_analyzer.transport_proto_frequency_map)
    {
        proto_stream << proto << " = " << freq << "\n";
    }
    proto_stream.close();

    return 0;
}