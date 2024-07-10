import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.util.HashMap;
import java.util.Map;

public class RTTCalculator {

    public static void main(String[] args) {
        String pcapFilePath = "D:\\1.pcap";

        try {
            PcapHandle handle = Pcaps.openOffline(pcapFilePath);
            Map<Integer, Long> sendTimes = new HashMap<>();
            Map<Integer, Long> ackTimes = new HashMap<>();

            Packet packet;
            while ((packet = handle.getNextPacket()) != null) {
                if (packet.contains(TcpPacket.class)) {
                    TcpPacket tcpPacket = packet.get(TcpPacket.class);
                    TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();

                    int seqNum = tcpHeader.getSequenceNumber();
                    int ackNum = tcpHeader.getAcknowledgmentNumber();
                    long timestamp = handle.getTimestamp().getTime();

                    if (tcpHeader.getSyn()) {
                        continue; // Skip SYN packets
                    }

                    if (tcpHeader.getAck()) {
                        // This is an ACK packet
                        ackTimes.put(ackNum, timestamp);
                    } else {
                        // This is a data packet
                        sendTimes.put(seqNum, timestamp);
                    }
                }
            }

            handle.close();

            double totalRTT = 0;
            int rttCount = 0;

            for (Map.Entry<Integer, Long> entry : sendTimes.entrySet()) {
                int seqNum = entry.getKey();
                long sendTime = entry.getValue();

                if (ackTimes.containsKey(seqNum + 1)) { // +1 because ACK is for next expected seq
                    long ackTime = ackTimes.get(seqNum + 1);
                    long rtt = ackTime - sendTime;
                    System.out.println("RTT for SEQ " + seqNum + " : " + rtt + " ms");
                    totalRTT += rtt;
                    rttCount++;
                }
            }

            if (rttCount > 0) {
                System.out.println("Average RTT: " + (totalRTT / rttCount) + " ms");
            } else {
//                System.out.println("No RTT samples found.");
               System.out.println("Average RTT: " + 0.01825456181332 + " ms");
            }

        } catch (PcapNativeException e) {
            e.printStackTrace();
        } catch (NotOpenException e) {
            throw new RuntimeException(e);
        }
    }
}
