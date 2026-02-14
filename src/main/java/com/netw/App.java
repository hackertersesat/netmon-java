package com.netw;

import java.util.List;

import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;

public class App 
{
    private static final int SNAPLEN_BYTES = 65536;
    private static final int READ_TIMEOUT_MS = 10;
    private static final int MAX_PAYLOAD_PREVIEW_BYTES = 8192;

    private enum OutputFormat {
        RAW,
        JSON
    }

    private static final class CliConfig {
        String ifaceName = null;
        Integer ifaceIndex = null;
        boolean listIfaces = false;
        boolean interactive = false;
        boolean showHelp = false;
        OutputFormat format = OutputFormat.RAW;
        boolean formatExplicit = false;
    }

    public static void main( String[] args )
    {
        try {
            CliConfig cfg = parseArgs(args);

            if (cfg.showHelp) {
                printUsage();
                return;
            }

            List<PcapNetworkInterface> ifaces = Pcaps.findAllDevs();
            if (ifaces == null || ifaces.isEmpty()) {
                System.err.println("No network interfaces found (Pcaps.findAllDevs returned empty).");
                return;
            }

            if (cfg.listIfaces) {
                printInterfaces(ifaces);
                return;
            }

            PcapNetworkInterface nif = null;
            if (cfg.interactive || (cfg.ifaceName == null && cfg.ifaceIndex == null)) {
                printInterfaces(ifaces);
                Integer idx = promptForInterfaceIndex(ifaces);
                if (idx == null) {
                    System.err.println("No interface selected.");
                    return;
                }
                nif = ifaces.get(idx.intValue());

                // If the user asked for interactive mode and did not set a format via flags, ask here.
                if (cfg.interactive && !cfg.formatExplicit) {
                    OutputFormat fmt = promptForOutputFormat();
                    if (fmt == null) {
                        System.err.println("No output format selected.");
                        return;
                    }
                    cfg.format = fmt;
                }
            } else {
                nif = selectInterface(cfg, ifaces);
            }
            if (nif == null) {
                System.err.println("Selected interface not found.");
                System.err.println();
                printInterfaces(ifaces);
                return;
            }

            final PcapNetworkInterface selectedNif = nif;

            // Handler
            final PcapHandle handle =
                selectedNif.openLive(SNAPLEN_BYTES, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT_MS);

            String desc = selectedNif.getDescription();
            System.out.println(
                "Listening on " + selectedNif.getName() + (desc != null ? (" (" + desc + ")") : "") + "... (Ctrl+C to stop)");

            final AtomicLong frameNo = new AtomicLong(0);

            // Listener
            PacketListener listener = new PacketListener() {
                @Override
                public void gotPacket(Packet packet) {
                    long n = frameNo.incrementAndGet();
                    Timestamp ts = null;
                    try {
                        ts = handle.getTimestamp();
                    } catch (Exception ignored) {
                        // Some platforms/versions may not provide timestamps reliably.
                    }

                    switch (cfg.format) {
                        case RAW:
                            printRawLike(System.out, selectedNif.getName(), n, packet, ts);
                            break;
                        case JSON:
                            System.out.println(packetToJson(selectedNif.getName(), n, packet, ts));
                            break;
                        default:
                            printRawLike(System.out, selectedNif.getName(), n, packet, ts);
                            break;
                    }
                }
            };

            // Infinite loop
            handle.loop(-1, listener);
            
            handle.close();
            System.out.println("Selesai.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static CliConfig parseArgs(String[] args) {
        CliConfig cfg = new CliConfig();
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "-h":
                case "--help":
                    cfg.showHelp = true;
                    break;
                case "-l":
                case "--list":
                    cfg.listIfaces = true;
                    break;
                case "-I":
                case "--interactive":
                    cfg.interactive = true;
                    break;
                case "-i":
                case "--iface":
                case "--interface":
                    if (i + 1 >= args.length) {
                        throw new IllegalArgumentException(a + " requires a value (interface name).");
                    }
                    cfg.ifaceName = args[++i];
                    break;
                case "--index":
                    if (i + 1 >= args.length) {
                        throw new IllegalArgumentException(a + " requires a value (interface index).");
                    }
                    cfg.ifaceIndex = Integer.parseInt(args[++i]);
                    break;
                case "-f":
                case "--format":
                    if (i + 1 >= args.length) {
                        throw new IllegalArgumentException(a + " requires a value (raw|json).");
                    }
                    cfg.format = parseFormat(args[++i]);
                    cfg.formatExplicit = true;
                    break;
                case "--raw":
                    cfg.format = OutputFormat.RAW;
                    cfg.formatExplicit = true;
                    break;
                case "--json":
                    cfg.format = OutputFormat.JSON;
                    cfg.formatExplicit = true;
                    break;
                default:
                    throw new IllegalArgumentException("Unknown argument: " + a);
            }
        }
        if (cfg.ifaceName != null && cfg.ifaceIndex != null) {
            throw new IllegalArgumentException("Use either --iface or --index (not both).");
        }
        return cfg;
    }

    private static OutputFormat parseFormat(String v) {
        if (v == null) throw new IllegalArgumentException("--format requires a value.");
        String s = v.trim().toLowerCase();
        switch (s) {
            case "raw":
                return OutputFormat.RAW;
            case "json":
                return OutputFormat.JSON;
            default:
                throw new IllegalArgumentException("Unknown format: " + v + " (expected raw|json)");
        }
    }

    private static void printUsage() {
        System.out.println("Usage: mvn -q exec:java -Dexec.mainClass=com.netw.App -Dexec.args=\"<args>\"");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  -h, --help            Show help");
        System.out.println("  -l, --list            List available network interfaces and exit");
        System.out.println("  -I, --interactive     Prompt to select an interface");
        System.out.println("  -i, --iface <name>    Capture from interface by name (e.g. en0, eth0, Wi-Fi)");
        System.out.println("      --index <n>       Capture from interface by index (see --list)");
        System.out.println("  -f, --format <fmt>    Output format: raw|json (default: raw)");
        System.out.println("      --raw             Same as --format raw");
        System.out.println("      --json            Same as --format json (NDJSON, one packet per line)");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  mvn -q exec:java -Dexec.mainClass=com.netw.App -Dexec.args=\"--list\"");
        System.out.println("  mvn -q exec:java -Dexec.mainClass=com.netw.App -Dexec.args=\"--interactive\"");
        System.out.println("  mvn -q exec:java -Dexec.mainClass=com.netw.App -Dexec.args=\"--iface en0\"");
        System.out.println("  mvn -q exec:java -Dexec.mainClass=com.netw.App -Dexec.args=\"--index 0\"");
        System.out.println("  mvn -q exec:java -Dexec.mainClass=com.netw.App -Dexec.args=\"--interactive --json\"");
    }

    private static void printInterfaces(List<PcapNetworkInterface> ifaces) {
        System.out.println("Available interfaces:");
        for (int idx = 0; idx < ifaces.size(); idx++) {
            PcapNetworkInterface nif = ifaces.get(idx);
            String name = nif.getName();
            String desc = nif.getDescription();
            System.out.println("  [" + idx + "] " + name + (desc != null ? (" - " + desc) : ""));
        }
    }

    private static PcapNetworkInterface selectInterface(CliConfig cfg, List<PcapNetworkInterface> ifaces)
        throws PcapNativeException {
        if (cfg.ifaceName != null) {
            // Prefer pcap's direct lookup so the name matches libpcap exactly.
            return Pcaps.getDevByName(cfg.ifaceName);
        }

        if (cfg.ifaceIndex != null) {
            int idx = cfg.ifaceIndex.intValue();
            if (idx < 0 || idx >= ifaces.size()) {
                throw new IllegalArgumentException("--index out of range: " + idx);
            }
            return ifaces.get(idx);
        }

        // Default: pick the first device returned by libpcap.
        return ifaces.get(0);
    }

    private static Integer promptForInterfaceIndex(List<PcapNetworkInterface> ifaces) throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        while (true) {
            System.out.print("Select interface index (0-" + (ifaces.size() - 1) + ", empty = 0, q = quit): ");
            String line = br.readLine();
            if (line == null) return null;
            line = line.trim();
            if (line.isEmpty()) return Integer.valueOf(0);
            if (line.equalsIgnoreCase("q") || line.equalsIgnoreCase("quit")) return null;
            try {
                int idx = Integer.parseInt(line);
                if (idx < 0 || idx >= ifaces.size()) {
                    System.out.println("Index out of range.");
                    continue;
                }
                return Integer.valueOf(idx);
            } catch (NumberFormatException e) {
                System.out.println("Please enter a number.");
            }
        }
    }

    private static OutputFormat promptForOutputFormat() throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        while (true) {
            System.out.print("Select output format (raw/json, empty = raw, q = quit): ");
            String line = br.readLine();
            if (line == null) return null;
            line = line.trim();
            if (line.isEmpty()) return OutputFormat.RAW;
            if (line.equalsIgnoreCase("q") || line.equalsIgnoreCase("quit")) return null;
            try {
                return parseFormat(line);
            } catch (IllegalArgumentException e) {
                System.out.println("Please enter one of: raw, json.");
            }
        }
    }

    private static void printRawLike(PrintStream out, String iface, long frameNo, Packet packet, Timestamp ts) {
        String tsStr = (ts != null) ? toIsoInstant(ts) : null;
        int len = packet.length();

        // Wireshark-ish header plus pcap4j's decoded packet representation.
        StringBuilder sb = new StringBuilder();
        sb.append("Frame ").append(frameNo).append(": ").append(len).append(" bytes");
        sb.append(" on interface ").append(iface);
        if (tsStr != null) sb.append(" at ").append(tsStr);
        sb.append("\n");
        sb.append(rewriteHexStreamAsText(packet.toString(), packet)).append("\n");
        out.print(sb.toString());
    }

    private static String packetToJson(String iface, long frameNo, Packet packet, Timestamp ts) {
        String tsStr = (ts != null) ? toIsoInstant(ts) : null;
        int len = packet.length();
        HumanPayload hp = humanizePayload(packet);
        String rawText = hp.text;

        EthernetPacket eth = packet.get(EthernetPacket.class);
        IpV4Packet ip4 = packet.get(IpV4Packet.class);
        IpV6Packet ip6 = packet.get(IpV6Packet.class);
        TcpPacket tcp = packet.get(TcpPacket.class);
        UdpPacket udp = packet.get(UdpPacket.class);

        StringBuilder sb = new StringBuilder(512);
        sb.append("{");
        sb.append("\"frame\":").append(frameNo).append(",");
        if (tsStr != null) sb.append("\"timestamp\":\"").append(escapeJson(tsStr)).append("\",");
        sb.append("\"interface\":\"").append(escapeJson(iface)).append("\",");
        sb.append("\"length\":").append(len).append(",");

        sb.append("\"layers\":{");
        boolean wrote = false;

        if (eth != null) {
            wrote = true;
            sb.append("\"ethernet\":{");
            sb.append("\"src\":\"").append(escapeJson(String.valueOf(eth.getHeader().getSrcAddr()))).append("\",");
            sb.append("\"dst\":\"").append(escapeJson(String.valueOf(eth.getHeader().getDstAddr()))).append("\",");
            sb.append("\"type\":\"").append(escapeJson(String.valueOf(eth.getHeader().getType()))).append("\"");
            sb.append("}");
        }

        if (ip4 != null) {
            if (wrote) sb.append(",");
            wrote = true;
            sb.append("\"ipv4\":{");
            sb.append("\"src\":\"").append(escapeJson(ip4.getHeader().getSrcAddr().getHostAddress())).append("\",");
            sb.append("\"dst\":\"").append(escapeJson(ip4.getHeader().getDstAddr().getHostAddress())).append("\",");
            sb.append("\"protocol\":\"").append(escapeJson(String.valueOf(ip4.getHeader().getProtocol()))).append("\",");
            sb.append("\"ttl\":").append(ip4.getHeader().getTtlAsInt());
            sb.append("}");
        } else if (ip6 != null) {
            if (wrote) sb.append(",");
            wrote = true;
            sb.append("\"ipv6\":{");
            sb.append("\"src\":\"").append(escapeJson(ip6.getHeader().getSrcAddr().getHostAddress())).append("\",");
            sb.append("\"dst\":\"").append(escapeJson(ip6.getHeader().getDstAddr().getHostAddress())).append("\",");
            sb.append("\"nextHeader\":\"").append(escapeJson(String.valueOf(ip6.getHeader().getNextHeader()))).append("\",");
            sb.append("\"hopLimit\":").append(ip6.getHeader().getHopLimitAsInt());
            sb.append("}");
        }

        if (tcp != null) {
            if (wrote) sb.append(",");
            wrote = true;
            sb.append("\"tcp\":{");
            sb.append("\"srcPort\":").append(tcp.getHeader().getSrcPort().valueAsInt()).append(",");
            sb.append("\"dstPort\":").append(tcp.getHeader().getDstPort().valueAsInt()).append(",");
            sb.append("\"seq\":").append(tcp.getHeader().getSequenceNumberAsLong()).append(",");
            sb.append("\"ack\":").append(tcp.getHeader().getAcknowledgmentNumberAsLong()).append(",");
            sb.append("\"flags\":\"").append(escapeJson(tcpFlags(tcp))).append("\"");
            sb.append("}");
        } else if (udp != null) {
            if (wrote) sb.append(",");
            wrote = true;
            sb.append("\"udp\":{");
            sb.append("\"srcPort\":").append(udp.getHeader().getSrcPort().valueAsInt()).append(",");
            sb.append("\"dstPort\":").append(udp.getHeader().getDstPort().valueAsInt()).append(",");
            sb.append("\"length\":").append(udp.getHeader().getLengthAsInt());
            sb.append("}");
        }

        sb.append("},");
        sb.append("\"raw_text\":\"").append(escapeJson(rawText)).append("\"");
        if (hp.info != null && !hp.info.isEmpty()) {
            sb.append(",\"raw_info\":\"").append(escapeJson(hp.info)).append("\"");
        }
        sb.append("}");
        return sb.toString();
    }

    private static String tcpFlags(TcpPacket tcp) {
        TcpPacket.TcpHeader h = tcp.getHeader();
        StringBuilder sb = new StringBuilder();
        if (h.getSyn()) sb.append("SYN,");
        if (h.getAck()) sb.append("ACK,");
        if (h.getFin()) sb.append("FIN,");
        if (h.getRst()) sb.append("RST,");
        if (h.getPsh()) sb.append("PSH,");
        if (h.getUrg()) sb.append("URG,");
        // pcap4j 1.8.2 doesn't expose ECN flags (ECE/CWR) on TcpHeader.
        if (sb.length() == 0) return "";
        sb.setLength(sb.length() - 1);
        return sb.toString();
    }

    private static String toIsoInstant(Timestamp ts) {
        Instant i = Instant.ofEpochMilli(ts.getTime());
        return i.toString();
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        StringBuilder out = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                    break;
            }
        }
        return out.toString();
    }

    private static String bytesToUtf8Text(byte[] data) {
        if (data == null || data.length == 0) return "";
        // Replacement for invalid sequences keeps output stable.
        return new String(data, StandardCharsets.UTF_8);
    }

    private static String bytesToAsciiPreview(byte[] data, int maxBytes) {
        if (data == null || data.length == 0) return "";
        int n = Math.min(data.length, maxBytes);
        StringBuilder sb = new StringBuilder(n + 32);
        for (int i = 0; i < n; i++) {
            int b = data[i] & 0xff;
            if (b == '\n' || b == '\r' || b == '\t') {
                sb.append((char) b);
            } else if (b >= 0x20 && b <= 0x7e) {
                sb.append((char) b);
            } else {
                sb.append('.');
            }
        }
        if (data.length > n) sb.append("... (truncated)");
        return sb.toString();
    }

    private static boolean looksLikeMostlyText(byte[] data) {
        if (data == null || data.length == 0) return false;
        int n = Math.min(data.length, 512);
        int printable = 0;
        for (int i = 0; i < n; i++) {
            int b = data[i] & 0xff;
            if (b == '\n' || b == '\r' || b == '\t') {
                printable++;
            } else if (b >= 0x20 && b <= 0x7e) {
                printable++;
            }
        }
        // If most bytes are printable ASCII/whitespace, treat it as text.
        return ((double) printable / (double) n) >= 0.85;
    }

    private static final class HumanPayload {
        final String text;
        final String info;
        HumanPayload(String text, String info) {
            this.text = (text != null) ? text : "";
            this.info = info;
        }
    }

    private static HumanPayload humanizePayload(Packet packet) {
        byte[] payload = getInnermostPayloadBytes(packet);
        if (payload == null || payload.length == 0) return new HumanPayload("", null);

        String info = guessPayloadInfo(packet, payload);

        if (looksLikeMostlyText(payload)) {
            String s = bytesToUtf8Text(payload);
            // Sanitize control characters (keep common whitespace).
            StringBuilder sb = new StringBuilder(s.length());
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (c == '\n' || c == '\r' || c == '\t') {
                    sb.append(c);
                } else if (Character.isISOControl(c)) {
                    sb.append('.');
                } else {
                    sb.append(c);
                }
            }
            return new HumanPayload(sb.toString(), info);
        }

        // Binary payload: show a clean ASCII preview instead of unreadable replacement characters.
        return new HumanPayload(bytesToAsciiPreview(payload, MAX_PAYLOAD_PREVIEW_BYTES), info);
    }

    private static String guessPayloadInfo(Packet packet, byte[] payload) {
        // Very small heuristics: just enough to explain why data isn't readable.
        int srcPort = -1;
        int dstPort = -1;

        TcpPacket tcp = packet.get(TcpPacket.class);
        if (tcp != null) {
            srcPort = tcp.getHeader().getSrcPort().valueAsInt();
            dstPort = tcp.getHeader().getDstPort().valueAsInt();
        } else {
            UdpPacket udp = packet.get(UdpPacket.class);
            if (udp != null) {
                srcPort = udp.getHeader().getSrcPort().valueAsInt();
                dstPort = udp.getHeader().getDstPort().valueAsInt();
            }
        }

        if (looksLikeTlsRecord(payload)) {
            return "Looks like TLS record data (typically encrypted).";
        }

        if (srcPort == 443 || dstPort == 443) {
            return "Port 443 traffic is usually TLS-encrypted, so payload will look like binary.";
        }

        if (looksLikeHttp(payload) || srcPort == 80 || dstPort == 80) {
            return "Looks like HTTP/plaintext application data.";
        }

        return null;
    }

    private static boolean looksLikeTlsRecord(byte[] p) {
        if (p == null || p.length < 5) return false;
        int contentType = p[0] & 0xff; // 0x14..0x17
        int major = p[1] & 0xff;       // 0x03
        int minor = p[2] & 0xff;       // 0x00..0x04
        if (major != 0x03) return false;
        if (minor > 0x04) return false;
        return contentType == 0x14 || contentType == 0x15 || contentType == 0x16 || contentType == 0x17;
    }

    private static boolean looksLikeHttp(byte[] p) {
        if (p == null || p.length < 4) return false;
        // Basic method/response checks.
        return startsWithAscii(p, "GET ")
            || startsWithAscii(p, "POST ")
            || startsWithAscii(p, "PUT ")
            || startsWithAscii(p, "HEAD ")
            || startsWithAscii(p, "DELETE ")
            || startsWithAscii(p, "OPTIONS ")
            || startsWithAscii(p, "HTTP/");
    }

    private static boolean startsWithAscii(byte[] p, String s) {
        if (p == null || s == null) return false;
        byte[] b = s.getBytes(StandardCharsets.US_ASCII);
        if (p.length < b.length) return false;
        for (int i = 0; i < b.length; i++) {
            if (p[i] != b[i]) return false;
        }
        return true;
    }

    private static String rewriteHexStreamAsText(String packetStr, Packet packet) {
        if (packetStr == null || packetStr.isEmpty() || packet == null) return packetStr;

        HumanPayload hp = humanizePayload(packet);

        String[] lines = packetStr.split("\\R", -1);
        StringBuilder out = new StringBuilder(packetStr.length() + Math.min(256, hp.text.length()));

        boolean skippingHexContinuation = false;
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];

            if (skippingHexContinuation) {
                if (looksLikeHexBytesLine(line)) {
                    continue;
                }
                skippingHexContinuation = false;
            }

            int hs = line.indexOf("Hex stream:");
            if (hs >= 0) {
                String prefix = line.substring(0, hs);
                out.append(prefix).append("Text: ").append(hp.text).append("\n");
                if (hp.info != null && !hp.info.isEmpty()) {
                    out.append(prefix).append("Info: ").append(hp.info).append("\n");
                }
                skippingHexContinuation = true;
                continue;
            }

            out.append(line);
            if (i != lines.length - 1) out.append("\n");
        }

        return out.toString();
    }

    private static boolean looksLikeHexBytesLine(String line) {
        if (line == null) return false;
        if (line.indexOf(':') >= 0) return false;
        if (line.indexOf('[') >= 0 || line.indexOf(']') >= 0) return false;

        String t = line.trim();
        if (t.isEmpty()) return false;

        String[] parts = t.split("\\s+");
        for (String p : parts) {
            if (p.length() != 2) return false;
            for (int i = 0; i < 2; i++) {
                char c = p.charAt(i);
                boolean hex = (c >= '0' && c <= '9')
                    || (c >= 'a' && c <= 'f')
                    || (c >= 'A' && c <= 'F');
                if (!hex) return false;
            }
        }
        return true;
    }

    private static byte[] getInnermostPayloadBytes(Packet packet) {
        Packet p = packet;
        while (p != null && p.getPayload() != null) {
            p = p.getPayload();
        }
        if (p != null) return p.getRawData();
        return packet.getRawData();
    }
}
