import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class TracePointers extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: TracePointers <output_dir>");
            return;
        }
        String outputDir = args[0];

        println("Starting TracePointers script...");

        String inputJsonPath = outputDir + "/shift_jis_refs.json";
        List<Map<String, Object>> textRefs = readJson(inputJsonPath);
        if (textRefs == null) {
            printerr("Could not read " + inputJsonPath);
            return;
        }

        Program program = currentProgram;
        List<Map<String, Object>> pointerEntries = new ArrayList<>();

        for (Map<String, Object> textRef : textRefs) {
            if (monitor.isCancelled()) {
                break;
            }

            long ramAddrLong = ((Number) textRef.get("ram_address")).longValue();
            Address targetAddr = currentAddress.getNewAddress(ramAddrLong);

            ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(targetAddr);
            List<Long> xrefs = new ArrayList<>();

            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                xrefs.add(fromAddr.getOffset());

                // Analyze the instruction referencing this text
                Instruction insn = program.getListing().getInstructionAt(fromAddr);
                if (insn != null) {
                    String mnemonic = insn.getMnemonicString();
                    
                    Map<String, Object> pointerEntry = new HashMap<>();
                    pointerEntry.put("pointer_address", fromAddr.getOffset());
                    pointerEntry.put("target_address", ramAddrLong);
                    
                    long fileOffset = fromAddr.getOffset() - 0x80010000L + 2048;
                    pointerEntry.put("file_offset", fileOffset);

                    if (mnemonic.equals("addiu") || mnemonic.equals("ori")) {
                        Instruction prev = insn.getPrevious();
                        if (prev != null && prev.getMnemonicString().equals("lui")) {
                            pointerEntry.put("instruction_type", "lui_" + mnemonic);
                            pointerEntry.put("file_offset", prev.getAddress().getOffset() - 0x80010000L + 2048);
                        } else {
                            pointerEntry.put("instruction_type", "split_lower");
                        }
                    } else if (insn.getOperandReferences(0).length > 0) {
                         pointerEntry.put("instruction_type", "direct");
                    } else {
                        pointerEntry.put("instruction_type", "unknown");
                    }
                    pointerEntries.add(pointerEntry);
                }
            }

            // Secondary Pass: Brute-force search for 32-bit static data pointers (Little Endian)
            // Ghidra's auto-analyzer routinely misses arrays of unstructured pointers in `.rodata`.
            byte[] targetBytes = new byte[] {
                (byte) (ramAddrLong & 0xFF),
                (byte) ((ramAddrLong >> 8) & 0xFF),
                (byte) ((ramAddrLong >> 16) & 0xFF),
                (byte) ((ramAddrLong >> 24) & 0xFF)
            };

            Address searchAddr = program.getMinAddress();
            while (searchAddr != null && searchAddr.compareTo(program.getMaxAddress()) < 0) {
                searchAddr = program.getMemory().findBytes(searchAddr, targetBytes, null, true, monitor);
                if (searchAddr != null) {
                    // Check if we already found this via auto-analysis to avoid duplicates
                    if (!xrefs.contains(searchAddr.getOffset())) {
                        xrefs.add(searchAddr.getOffset());

                        Map<String, Object> pointerEntry = new HashMap<>();
                        pointerEntry.put("pointer_address", searchAddr.getOffset());
                        pointerEntry.put("target_address", ramAddrLong);
                        
                        long fileOffset = searchAddr.getOffset() - 0x80010000L + 2048;
                        pointerEntry.put("file_offset", fileOffset);
                        pointerEntry.put("instruction_type", "data_pointer");

                        pointerEntries.add(pointerEntry);
                    }
                    searchAddr = searchAddr.add(4); // Advance past this pointer
                }
            }
            textRef.put("xrefs", xrefs);
        }

        Map<String, Object> output = new HashMap<>();
        output.put("pointers", pointerEntries);
        
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("total_text_refs_analyzed", textRefs.size());
        metadata.put("total_pointers_found", pointerEntries.size());
        output.put("metadata", metadata);

        println("Found " + pointerEntries.size() + " pointer references. Writing to JSON...");
        writeJson(output, outputDir + "/pointer_map.json");
        
        // Rewrite the updated textRefs with the new xrefs
        writeJson(textRefs, inputJsonPath);
    }

    private List<Map<String, Object>> readJson(String filePath) {
        Gson gson = new Gson();
        try (FileReader reader = new FileReader(filePath)) {
            java.lang.reflect.Type type = new TypeToken<List<Map<String, Object>>>() {}.getType();
            return gson.fromJson(reader, type);
        } catch (IOException e) {
            return null;
        }
    }

    private void writeJson(Object data, String filePath) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        try (FileWriter writer = new FileWriter(filePath)) {
            gson.toJson(data, writer);
            println("Successfully documented pointers in: " + filePath);
        } catch (IOException e) {
            printerr("Error writing JSON: " + e.getMessage());
        }
    }
}
