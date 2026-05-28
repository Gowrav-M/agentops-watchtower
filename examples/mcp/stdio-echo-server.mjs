import readline from "node:readline";

const lines = readline.createInterface({ input: process.stdin });

lines.on("line", (line) => {
  const message = JSON.parse(line);
  const toolName = message.params?.name ?? "unknown";
  process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id: message.id, result: { ok: true, toolName } })}\n`);
});
