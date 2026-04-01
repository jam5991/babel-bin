import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.address.Address;

public class FindShiftJIS extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: FindShiftJIS <output_dir>");
            return;
        }
        String outputDir = args[0];

        println("Starting FindShiftJIS script...");

        Program program = currentProgram;
        Memory mem = program.getMemory();

        List<Map<String, Object>> results = new ArrayList<>();

        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized() || !block.isExecute() && !block.isRead()) {
                continue;
            }

            println("Scanning block: " + block.getName());

            Address start = block.getStart();
            Address end = block.getEnd();

            Address current = start;

            while (current.compareTo(end) < 0) {
                if (monitor.isCancelled()) {
                    break;
                }

                try {
                    byte b = mem.getByte(current);

                    if (isSjisLeadByte(b)) {
                        Address clusterStart = current;
                        int length = 0;
                        StringBuilder decodedPreview = new StringBuilder();

                        while (current.compareTo(end) < 0) {
                            byte b1 = mem.getByte(current);

                            if (isSjisLeadByte(b1)) {
                                Address next = current.add(1);
                                if (next.compareTo(end) >= 0) {
                                    break;
                                }
                                byte b2 = mem.getByte(next);
                                if (isSjisTrailByte(b2)) {
                                    length += 2;
                                    decodedPreview.append(decodeSJIS(b1, b2));
                                    current = current.add(2);
                                } else {
                                    break;
                                }
                            } else if (b1 >= 0x20 && b1 <= 0x7E) {
                                length++;
                                decodedPreview.append((char) b1);
                                current = current.add(1);
                            } else if (b1 == 0x0A || b1 == 0x0D || b1 == 0x00) {
                                length++;
                                if (b1 == 0x0A)
                                    decodedPreview.append("↵");
                                if (b1 == 0x00)
                                    decodedPreview.append("∅");
                                current = current.add(1);
                                if (b1 == 0x00) {
                                    break;
                                }
                            } else {
                                break;
                            }
                        }

                        if (length >= 8) {
                            Map<String, Object> entry = new HashMap<>();

                            // File offsets in PSX
                            // Assumes base address is 0x80010000 and Header is 2048
                            long fileOffset = clusterStart.getOffset() - 0x80010000L + 2048;

                            entry.put("offset", fileOffset);
                            entry.put("ram_address", clusterStart.getOffset());
                            entry.put("length", length);
                            entry.put("decoded_text", decodedPreview.toString());
                            results.add(entry);
                        } else {
                            current = clusterStart.add(1);
                        }
                    } else {
                        current = current.add(1);
                    }
                } catch (Exception e) {
                    current = current.add(1);
                }
            }
        }

        println("Found " + results.size() + " Shift-JIS clusters. Writing to JSON...");
        writeJson(results, outputDir + "/shift_jis_refs.json");
    }

    private boolean isSjisLeadByte(byte b) {
        int uByte = b & 0xFF;
        return (uByte >= 0x81 && uByte <= 0x9F) || (uByte >= 0xE0 && uByte <= 0xEF);
    }

    private boolean isSjisTrailByte(byte b) {
        int uByte = b & 0xFF;
        return (uByte >= 0x40 && uByte <= 0x7E) || (uByte >= 0x80 && uByte <= 0xFC);
    }

    private String decodeSJIS(byte b1, byte b2) {
        try {
            return new String(new byte[] { b1, b2 }, "Shift_JIS");
        } catch (Exception e) {
            return "?";
        }
    }

    private void writeJson(List<Map<String, Object>> data, String filePath) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        try (FileWriter writer = new FileWriter(filePath)) {
            gson.toJson(data, writer);
            println("Successfully documented strings in: " + filePath);
        } catch (IOException e) {
            printerr("Error writing JSON: " + e.getMessage());
        }
    }
}
