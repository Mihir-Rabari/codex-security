import { assertPublicText } from "./package-public-content.mjs";

const blockSize = 512;
function invalidTarEntry() {
  throw new Error("npm tarball contains an invalid tar entry.");
}

function headerText(header, start, end) {
  return header.subarray(start, end).toString("utf8").split("\0", 1)[0];
}

export function plainTarEntries(archiveBytes) {
  if (archiveBytes.byteLength % blockSize !== 0) invalidTarEntry();
  const entries = [];
  let offset = 0;

  while (offset + blockSize <= archiveBytes.byteLength) {
    const header = archiveBytes.subarray(offset, offset + blockSize);
    if (header.every((byte) => byte === 0)) {
      offset += blockSize;
      continue;
    }

    assertPublicText(header.toString("utf8"));
    const signature = header.subarray(257, 265).toString("latin1");
    const directory = header[156] === 0x35;
    if (
      (header[156] !== 0 && header[156] !== 0x30 && !directory) ||
      (signature !== "ustar\0" + "00" && signature !== "ustar  \0")
    ) {
      invalidTarEntry();
    }

    const name = headerText(header, 0, 100);
    // GNU headers use this area for timestamps and sparse-file metadata.
    const prefix =
      signature === "ustar\0" + "00" ? headerText(header, 345, 500) : "";
    const path = prefix === "" ? name : `${prefix}/${name}`;
    if (name === "" || path.endsWith("/") !== directory) invalidTarEntry();
    assertPublicText(path);

    const sizeField = headerText(header, 124, 136).trim();
    if (!/^[0-7]*$/u.test(sizeField)) invalidTarEntry();
    const size = Number.parseInt(sizeField || "0", 8);
    const contentsEnd = offset + blockSize + size;
    const nextOffset =
      offset + blockSize + Math.ceil(size / blockSize) * blockSize;
    if (nextOffset > archiveBytes.byteLength || (directory && size !== 0)) {
      invalidTarEntry();
    }
    assertPublicText(
      archiveBytes.subarray(contentsEnd, nextOffset).toString("utf8"),
    );

    entries.push({ path, size });
    offset = nextOffset;
  }

  return entries;
}
