import { assertPublicText } from "./package-public-content.mjs";

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

function sparseMap(contents) {
  let offset = 0;
  function number() {
    while (offset < contents.length) {
      const end = contents.indexOf(0x0a, offset);
      if (end === -1) invalidTarEntry();
      const line = contents.subarray(offset, end).toString("ascii");
      offset = end + 1;
      if (line.startsWith("#")) continue;
      if (!/^[0-9]*$/u.test(line)) invalidTarEntry();
      return Number(line);
    }
    invalidTarEntry();
  }
  const count = number();
  const extents = [];
  for (let index = 0; index < count; index++) {
    extents.push({ offset: number(), size: number() });
  }
  const dataOffset = Math.ceil(offset / blockSize) * blockSize;
  if (dataOffset > contents.length) invalidTarEntry();
  return { contents, extents, dataOffset };
}

export function assertStoredSparseContents(sparseFiles, extractedFiles) {
  for (const [path, { contents, extents, dataOffset }] of sparseFiles) {
    const extracted = extractedFiles.get(path);
    let metadata;
    // GNU tar pads stored extents; libarchive also accepts packed extents.
    for (const padded of [false, true]) {
      let offset = dataOffset;
      const discarded = [contents.subarray(0, dataOffset)];
      const matches = extents.every((extent, index) => {
        const end = offset + extent.size;
        if (
          !contents
            .subarray(offset, end)
            .equals(
              extracted.subarray(extent.offset, extent.offset + extent.size),
            )
        )
          return false;
        const next =
          padded && index < extents.length - 1
            ? Math.ceil(end / blockSize) * blockSize
            : end;
        discarded.push(contents.subarray(end, next));
        offset = next;
        return true;
      });
      if (matches) {
        discarded.push(contents.subarray(offset));
        metadata = Buffer.concat(discarded);
        break;
      }
    }
    if (metadata === undefined) invalidTarEntry();
    assertPublicText(metadata.toString("utf8"));
  }
}

export function readTarArchive(archiveBytes) {
  const entries = [];
  const archiveFiles = new Map();
  const archiveMetadata = [];
  const sparseFiles = new Map();
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
        const contents = archiveBytes.subarray(offset + blockSize, contentsEnd);
        if (
          Number.parseInt(nextAttributes.get("GNU.sparse.major"), 10) === 1 &&
          /\.(?:png|br(?:\.part-[0-9]+)?)$/iu.test(path)
        )
          sparseFiles.set(path, sparseMap(contents));
        else archiveFiles.set(path, contents);
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
  const deferredStreams = new Set(
    [...sparseFiles.keys()].map((path) => path.replace(/\.part-[0-9]+$/iu, "")),
  );
  const deferredFiles = new Map();
  for (const [path, contents] of archiveFiles) {
    if (deferredStreams.has(path.replace(/\.part-[0-9]+$/iu, ""))) {
      deferredFiles.set(path, contents);
      archiveFiles.delete(path);
    }
  }
  return {
    entries,
    files: archiveFiles,
    metadata: Buffer.concat(archiveMetadata),
    sparseFiles,
    deferredFiles,
  };
}
