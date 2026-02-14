# netmon-java

Simple packet capture / network monitoring CLI written in Java using Pcap4J (libpcap).

## Requirements

- Java (JDK) 25+
- Maven 3.9+
- Packet capture library
  - macOS / Linux: `libpcap` (usually already present)
  - Windows: Npcap (WinPcap API compatible mode)

Note: capturing packets usually requires elevated privileges (for example `sudo` on macOS/Linux).

## Build

```sh
mvn clean package
```

This produces:

- `target/netmon-1.0.jar` (regular jar)
- `target/netmon-1.0-all.jar` (runnable "fat jar" with dependencies)

## Run (fat jar)

```sh
java -jar target/netmon-1.0-all.jar --help
java -jar target/netmon-1.0-all.jar --list
java -jar target/netmon-1.0-all.jar --interactive
java -jar target/netmon-1.0-all.jar --iface en0
java -jar target/netmon-1.0-all.jar --index 0
java -jar target/netmon-1.0-all.jar --interactive --json
```

If you get permission errors, try:

```sh
sudo java -jar target/netmon-1.0-all.jar --interactive
```

## Output formats

- `--raw` (default): human-readable output
- `--json`: NDJSON (one JSON object per line, good for piping into tools)

## Run (dev mode via Maven)

```sh
mvn -q exec:java -Dexec.mainClass=com.netw.App -Dexec.args="--list"
mvn -q exec:java -Dexec.mainClass=com.netw.App -Dexec.args="--interactive --json"
```
