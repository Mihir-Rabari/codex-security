export function regularTarListingLines(listing) {
  const lines = listing.split(/\r?\n/u).filter(Boolean);
  if (lines.some((line) => !line.startsWith("d") && !line.startsWith("-"))) {
    throw new Error(
      "npm tarball contains a non-regular entry (symbolic or hard link, device, or pipe).",
    );
  }
  return lines;
}

export function assertTarListingSizes(lines, maximum) {
  let expandedBytes = 0;
  for (const line of lines) {
    if (line.startsWith("d")) continue;
    // GNU combines numeric owners; BSD lists the link count, UID and GID.
    const match = /^\S+\s+(?:\d+\/\d+\s+|\d+\s+\d+\s+\d+\s+)(\d+)\s/u.exec(
      line,
    );
    const size = match === null ? NaN : Number(match[1]);
    if (!Number.isSafeInteger(size) || size > maximum - expandedBytes)
      throw new Error("npm tarball contains an invalid tar entry.");
    expandedBytes += size;
  }
}
