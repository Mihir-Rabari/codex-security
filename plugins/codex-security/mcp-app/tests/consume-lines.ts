export function consumeLines(buffer: string, consume: (line: string) => void) {
  let newline = buffer.indexOf("\n");
  while (newline >= 0) {
    const line = buffer.slice(0, newline).trim();
    buffer = buffer.slice(newline + 1);
    if (line) consume(line);
    newline = buffer.indexOf("\n");
  }
  return buffer;
}
