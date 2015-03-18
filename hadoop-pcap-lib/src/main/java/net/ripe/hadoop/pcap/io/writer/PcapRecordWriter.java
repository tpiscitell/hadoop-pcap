package net.ripe.hadoop.pcap.io.writer;

import net.ripe.hadoop.pcap.packet.DataPacket;
import net.ripe.hadoop.pcap.packet.Packet;

import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.ObjectWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapred.RecordWriter;
import org.apache.hadoop.mapred.Reporter;
import org.apache.hadoop.fs.FSDataOutputStream;

import java.io.IOException;


/**
 * Created by tpiscite on 3/17/15.
 */
public class PcapRecordWriter implements RecordWriter<Text, BytesWritable> {

    FSDataOutputStream out;

    public PcapRecordWriter (FSDataOutputStream out) {
        this.out = out;
    }

    public void write(Text key, BytesWritable value) throws IOException {
        /**
         * getBytes() returns the backing byte array which is padded. See:
         * https://issues.apache.org/jira/browse/HADOOP-6298
         */
        byte[] packetData = new byte[value.getLength()];
        System.arraycopy(value.getBytes(), 0, packetData, 0, value.getLength());
        out.write(packetData);
    }

    public void close(Reporter reporter) throws IOException {
        out.close();
    }
}
