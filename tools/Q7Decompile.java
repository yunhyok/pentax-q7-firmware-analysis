// Targeted static decompilation. No firmware code is executed.
// @category Q7
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class Q7Decompile extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) throw new IllegalArgumentException("symbols.tsv seeds.tsv output-directory");
        Path output = Path.of(args[2]);
        Files.createDirectories(output);
        for (String line : Files.readAllLines(Path.of(args[0]))) {
            String[] parts = line.split("\\t", 2);
            Address a = toAddr(Long.parseUnsignedLong(parts[0], 16));
            if (currentProgram.getMemory().contains(a)) {
                try { createLabel(a, parts[1], true); } catch (Exception ignored) { }
            }
        }
        List<Function> functions = new ArrayList<>();
        for (String line : Files.readAllLines(Path.of(args[1]))) {
            String[] parts = line.split("\\t", 3);
            Address a = toAddr(Long.parseUnsignedLong(parts[0], 16));
            Address end = toAddr(Long.parseUnsignedLong(parts[1], 16) - 1);
            // Sidecar extents are candidate boundaries; the evidence retains this limitation.
            Function f = getFunctionAt(a);
            if (f == null) f = currentProgram.getFunctionManager().createFunction(parts[2], a, new AddressSet(a, end), SourceType.USER_DEFINED);
            disassemble(a);
            if (f != null) functions.add(f);
        }
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        StringBuilder meta = new StringBuilder("address\tname\tcompleted\ttimed_out\tbody_bytes\terror\n");
        for (Function f : functions) {
            monitor.checkCancelled();
            DecompileResults r = decompiler.decompileFunction(f, 30, monitor);
            String key = f.getEntryPoint().toString();
            if (r.decompileCompleted()) Files.writeString(output.resolve(key + ".c"), r.getDecompiledFunction().getC(), StandardCharsets.UTF_8);
            StringBuilder asm = new StringBuilder();
            InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (it.hasNext()) { Instruction ins = it.next(); asm.append(ins.getAddress()).append("\t").append(ins).append("\n"); }
            Files.writeString(output.resolve(key + ".asm"), asm, StandardCharsets.UTF_8);
            meta.append(key).append('\t').append(f.getName()).append('\t').append(r.decompileCompleted()).append('\t').append(r.isTimedOut()).append('\t').append(f.getBody().getNumAddresses()).append('\t').append(r.getErrorMessage().replace('\n',' ').replace('\t',' ')).append('\n');
        }
        Files.writeString(output.resolve("results.tsv"), meta, StandardCharsets.UTF_8);
        decompiler.dispose();
        println("Q7_DECOMPILED " + functions.size());
    }
}
