package net.ripe.hadoop.pcap.io;

import java.lang.String;
import java.io.IOException;

import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.ObjectWritable;
import org.apache.hadoop.mapred.FileOutputFormat;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.MapWritable;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.mapred.RecordWriter;
import org.apache.hadoop.util.Progressable;

import net.ripe.hadoop.pcap.io.writer.PcapRecordWriter;
import net.ripe.hadoop.pcap.PcapReaderUtil;
/**
 * Created by tpiscite on 3/17/15.
 */
public class PcapOutputFormat extends FileOutputFormat {

    public static final int MAGIC_NUMBER = 0xA1B2C3D4;
    public static final short MAJOR_VERSION = 2;
    public static final short MINOR_VERSION = 4;
    public static final int THIS_ZONE = 0;
    public static final int SIG_FIGS = 0;
    public static final int SNAP_LEN =  65535;
    public static final int LINK_TYPE = 1; /* only support EN10MB for now */
    public static final String REVERSE_HEADER_KEY = "net.ripe.hadoop.pcap.io.writer.reverseKey";

    public RecordWriter<Text, BytesWritable> getRecordWriter(FileSystem ignored, JobConf job, String name, Progressable progress)  throws IOException {

        Path file = FileOutputFormat.getTaskOutputPath(job, name);
        FileSystem fs = file.getFileSystem(job);
        FSDataOutputStream fileOut = fs.create(file, progress);

        writePcapHeader(fileOut, job.getBoolean(REVERSE_HEADER_KEY, true));
        return new PcapRecordWriter(fileOut);
    }

    private byte[] intToByteArray(int d, boolean reverse) {
        if (reverse) {
            return new byte[] { (byte) d, (byte) (d >>> 8), (byte) (d >>> 16), (byte) (d >>> 24) };
        } else {
            return new byte[]{(byte) (d >>> 24), (byte) (d >>> 16), (byte) (d >>> 8), (byte) d};
        }
    }

    private byte[] shortToByteArray(short s, boolean reverse) {
        if (reverse) {
            return new byte[] { (byte) s, (byte) (s >>> 8) };
        } else {
            return new byte[] { (byte) (s >>> 8), (byte) s };
        }
    }

    /**
     * Write the Libpcap file header. See: https://wiki.wireshark.org/Development/LibpcapFileFormat
     */
    private void writePcapHeader(FSDataOutputStream out, boolean reverse) throws IOException {
        out.write(intToByteArray(MAGIC_NUMBER, reverse));
        out.write(shortToByteArray(MAJOR_VERSION, reverse));
        out.write(shortToByteArray(MINOR_VERSION, reverse));
        out.write(intToByteArray(THIS_ZONE, reverse));
        out.write(intToByteArray(SIG_FIGS, reverse));
        out.write(intToByteArray(SNAP_LEN, reverse));
        out.write(intToByteArray(LINK_TYPE, reverse));
    }
}
