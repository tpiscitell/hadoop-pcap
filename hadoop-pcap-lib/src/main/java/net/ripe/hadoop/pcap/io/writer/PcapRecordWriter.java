package net.ripe.hadoop.pcap.io.writer;

import net.ripe.hadoop.pcap.packet.DataPacket;

import org.apache.hadoop.mapreduce.RecordWriter;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapreduce.MapWriteable;

import java.io.DataOutputStream;

/**
 * Created by tpiscite on 3/17/15.
 */
public class PcapRecordWriter<Text, MapWriteable> implements RecordWriter<Text, MapWriteable> {

    PcapRecordWriter (DataOutputStream out) {
        this.out = out;
    }

    private void writePacket(Packet packet) {
        out.write(packet.get(DataPacket.PACKET_HEADER));
        out.write(packet.get(DataPacket.PACKET_HEADER));
    }
    public void write(Text key, MapWriteable value) {
        Packet packet = (Packet) value;
        if (packet.containsKey(DataPacket.PACKET_HEADER) && packet.containsKey(DataPacket.PACKET_DATA)) {
            writePacket(packet);
        }
    }
}
