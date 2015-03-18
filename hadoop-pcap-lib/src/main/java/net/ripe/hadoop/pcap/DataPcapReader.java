package net.ripe.hadoop.pcap;

import java.io.DataInputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.MathContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import net.ripe.hadoop.pcap.packet.Packet;
import net.ripe.hadoop.pcap.packet.DataPacket;

/**
 * Created by tpiscitell on 3/17/15.
 *
 * A PcapReader that saves pcapPacketHeader and packetData to the Packet and does not process packetData
 * beyond the L4 headers. Primary use case is to extract raw packets from pcap files on HDFS and collate
 * them into a single pcap file.
 */

public class DataPcapReader extends PcapReader {
    public static final Log LOG = LogFactory.getLog(DataPcapReader.class);

    public DataPcapReader(DataInputStream is) throws IOException {
        super(is);
    }

    // Only use this constructor for testcases
    protected DataPcapReader(LinkType lt) {
        super(lt);
    }

    protected Packet nextPacket() {
        pcapPacketHeader = new byte[PACKET_HEADER_SIZE];
        if (!readBytes(pcapPacketHeader))
            return null;

        Packet packet = createPacket();
        packet.put(DataPacket.PACKET_HEADER, pcapPacketHeader);

        long packetTimestamp = PcapReaderUtil.convertInt(pcapPacketHeader, TIMESTAMP_OFFSET, reverseHeaderByteOrder);
        packet.put(Packet.TIMESTAMP, packetTimestamp);

        long packetTimestampMicros = PcapReaderUtil.convertInt(pcapPacketHeader, TIMESTAMP_MICROS_OFFSET, reverseHeaderByteOrder);
        packet.put(Packet.TIMESTAMP_MICROS, packetTimestampMicros);

        // Prepare the timestamp with a BigDecimal to include microseconds
        BigDecimal packetTimestampUsec = new BigDecimal(packetTimestamp
                + (double) packetTimestampMicros/1000000, ts_mc);
        packet.put(Packet.TS_USEC, packetTimestampUsec);

        long packetSize = PcapReaderUtil.convertInt(pcapPacketHeader, CAP_LEN_OFFSET, reverseHeaderByteOrder);
        packetData = new byte[(int)packetSize];
        if (!readBytes(packetData))
            return packet;

        packet.put(DataPacket.PACKET_DATA, packetData);

        int ipStart = findIPStart(packetData);
        if (ipStart == -1)
            return packet;

        int ipProtocolHeaderVersion = getInternetProtocolHeaderVersion(packetData, ipStart);
        packet.put(Packet.IP_VERSION, ipProtocolHeaderVersion);

        if (ipProtocolHeaderVersion == 4 || ipProtocolHeaderVersion == 6) {
            int ipHeaderLen = getInternetProtocolHeaderLength(packetData, ipProtocolHeaderVersion, ipStart);
            packet.put(Packet.IP_HEADER_LENGTH, ipHeaderLen);

            int totalLength = 0;
            if (ipProtocolHeaderVersion == 4) {
                buildInternetProtocolV4Packet(packet, packetData, ipStart);
                totalLength = PcapReaderUtil.convertShort(packetData, ipStart + IP_TOTAL_LEN_OFFSET);
            } else if (ipProtocolHeaderVersion == 6) {
                buildInternetProtocolV6Packet(packet, packetData, ipStart);
                int payloadLength = PcapReaderUtil.convertShort(packetData, ipStart + IPV6_PAYLOAD_LEN_OFFSET);
                totalLength = payloadLength + IPV6_HEADER_SIZE;
            }

            String protocol = (String)packet.get(Packet.PROTOCOL);
            if (PROTOCOL_UDP == protocol ||
                    PROTOCOL_TCP == protocol) {

                byte[] packetPayload = buildTcpAndUdpPacket(packet, packetData, ipProtocolHeaderVersion, ipStart, ipHeaderLen, totalLength);
            }
        }

        return packet;
    }
}
