import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.regex.*;

/** Isolated protocol fixture: no Burp instance, network, credentials or target traffic. */
public final class Nim17McpFixture {
    public static void main(String[] args) throws Exception {
        for (int i = 0; i < 200; i++) System.err.println("diagnostic " + i);
        var reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        var writer = new PrintWriter(new OutputStreamWriter(System.out, StandardCharsets.UTF_8), true);
        for (String line; (line = reader.readLine()) != null;) {
            var id = Pattern.compile("\"id\"\\s*:\\s*(\"[^\"]*\"|[0-9]+)").matcher(line);
            if (!id.find()) continue;
            String result;
            if (line.contains("\"initialize\"")) {
                var version = Pattern.compile("\"protocolVersion\"\\s*:\\s*\"([^\"]+)\"").matcher(line);
                String protocol = version.find() ? version.group(1) : "2024-11-05";
                result = "{\"protocolVersion\":\"" + protocol + "\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"fixture\",\"version\":\"1\"}}";
            } else if (line.contains("\"tools/list\"")) {
                String name = line.contains("page2") ? "fail" : "echo";
                result = "{\"tools\":[{\"name\":\"" + name + "\",\"description\":\"Fixture tool\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"payload\":{\"type\":\"object\"}},\"required\":[\"payload\"]}}]";
                if (!line.contains("page2")) result += ",\"nextCursor\":\"page2\"";
                result += "}";
            } else if (line.contains("\"tools/call\"")) {
                boolean error = line.contains("\"fail\"");
                result = "{\"isError\":" + error + ",\"content\":[{\"type\":\"text\",\"text\":\"" + (error ? "fixture failure" : "fixture success") + "\"}]}";
            } else {
                result = "{}";
            }
            writer.println("{\"jsonrpc\":\"2.0\",\"id\":" + id.group(1) + ",\"result\":" + result + "}");
        }
    }
}
