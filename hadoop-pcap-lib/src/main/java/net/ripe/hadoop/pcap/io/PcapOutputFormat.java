package net.ripe.hadoop.pcap.io;

import org.apache.hadoop.mapreduce.FileOutputFormat;
import org.apache.hadoop.mapreduce.FileSystem;
import org.apache.hadoop.mapreduce.Text;
import org.apache.hadoop.mapreduce.MapWriteable;
import org.apache.hadoop.mapreduce.JobConf;
import org.apache.hadoop.mapreduce.Progresssable;

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

    public RecordWriter<Text, MapWriteable> getRecordWriter(FileSystem ignored, JobConf job, String name, Progressable progress) {

        Path file = FileOutputFormat.getTaskOutputPath(job, name);
        FileSystem fs = file.getFileSystem(job);
        FSDataOutputStream fileOut = fs.create(file, progress);

        writePcapHeader(fileOut);
        return new PcapRecordWriter<Text, MapWriteable>(fileOut);
    }

    /**
     * Write the Libpcap file header. See: https://wiki.wireshark.org/Development/LibpcapFileFormat
     */
    private void writePcapHeader(DataOutputStream out) {
        out.write(MAGIC_NUMBER);
        out.write(MAJOR_VERSION);
        out.write(MINOR_VERSION);
        out.write(THIS_ZONE);
        out.write(SIG_FIGS);
        out.write(SNAP_LEN);
        out.write(LINK_TYPE);
    }
}
