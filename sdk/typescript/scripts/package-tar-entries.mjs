import {
  assertPublicPackageContents,
  assertPublicText,
} from "./package-public-content.mjs";

const blockSize = 512;
function invalidTarEntry() {
  throw new Error("npm tarball contains an invalid tar entry.");
}

function headerText(header, start, end) {
  return header.subarray(start, end).toString("utf8").split("\0", 1)[0];
}

function paxAttributes(contents) {
  const attributes = new Map();
  let offset = 0;
  while (offset < contents.byteLength) {
    const separator = contents.indexOf(0x20, offset);
    const lengthField = contents.subarray(offset, separator).toString("ascii");
    if (separator === -1 || !/^[0-9]+$/u.test(lengthField)) invalidTarEntry();
    const end = offset + Number(lengthField);
    const equals = contents.indexOf(0x3d, separator + 1);
    if (
      end > contents.byteLength ||
      equals <= separator + 1 ||
      equals >= end - 1 ||
      contents[end - 1] !== 0x0a
    )
      invalidTarEntry();
    attributes.set(
      contents.subarray(separator + 1, equals).toString("utf8"),
      contents.subarray(equals + 1, end - 1).toString("utf8"),
    );
    offset = end;
  }
  return attributes;
}

export function plainTarEntries(archiveBytes, validateEntries = () => {}) {
  const entries = [];
  const archiveFiles = new Map();
  const archiveMetadata = [];
  let offset = 0;
  const globalAttributes = new Map();
  const nextAttributes = new Map();

  while (offset + blockSize <= archiveBytes.byteLength) {
    const header = archiveBytes.subarray(offset, offset + blockSize);
    if (header.every((byte) => byte === 0)) {
      archiveMetadata.push(header);
      offset += blockSize;
      continue;
    }

    const signature = header.subarray(257, 265).toString("latin1");
    const directory = header[156] === 0x35;
    const extended = header[156] === 0x78 || header[156] === 0x67;
    if (
      (header[156] !== 0 && header[156] !== 0x30 && !directory && !extended) ||
      (signature !== "ustar\0" + "00" &&
        signature !== "ustar  \0" &&
        signature !== "\0".repeat(8))
    ) {
      invalidTarEntry();
    }

    const name = headerText(header, 0, 100);
    // GNU headers use this area for timestamps and sparse-file metadata.
    const prefix =
      signature === "ustar\0" + "00" ? headerText(header, 345, 500) : "";
    const attribute = (key) =>
      nextAttributes.has(key)
        ? nextAttributes.get(key) || undefined
        : globalAttributes.get(key);
    const path =
      attribute("GNU.sparse.name") ??
      attribute("path") ??
      (prefix === "" ? name : `${prefix}/${name}`);
    if (!extended && (path === "" || path.endsWith("/") !== directory))
      invalidTarEntry();
    assertPublicText(path);

    const sizeField = headerText(header, 124, 136).trim();
    if (!/^[0-7]*$/u.test(sizeField)) invalidTarEntry();
    const paxSize = extended ? undefined : attribute("size");
    if (paxSize !== undefined && !/^[0-9]+$/u.test(paxSize)) invalidTarEntry();
    const size =
      paxSize === undefined
        ? Number.parseInt(sizeField || "0", 8)
        : Number(paxSize);
    const contentsEnd = offset + blockSize + size;
    const nextOffset =
      offset + blockSize + Math.ceil(size / blockSize) * blockSize;
    if (nextOffset > archiveBytes.byteLength || (directory && size !== 0)) {
      invalidTarEntry();
    }

    if (extended) {
      const contents = archiveBytes.subarray(offset + blockSize, contentsEnd);
      archiveMetadata.push(archiveBytes.subarray(offset, nextOffset));
      const destination =
        header[156] === 0x67 ? globalAttributes : nextAttributes;
      for (const [key, value] of paxAttributes(contents)) {
        if (destination === globalAttributes && value === "")
          destination.delete(key);
        else destination.set(key, value);
      }
    } else {
      if (directory)
        archiveMetadata.push(archiveBytes.subarray(offset, nextOffset));
      else {
        archiveFiles.set(
          path,
          archiveBytes.subarray(offset + blockSize, contentsEnd),
        );
        archiveMetadata.push(
          header,
          archiveBytes.subarray(contentsEnd, nextOffset),
        );
      }
      entries.push({ path, size });
      nextAttributes.clear();
    }
    offset = nextOffset;
  }

  if (archiveBytes.subarray(offset).some((byte) => byte !== 0))
    invalidTarEntry();
  validateEntries(entries);
  assertPublicPackageContents(archiveFiles, Buffer.concat(archiveMetadata));
  return entries;
}
