# Introduction

Zarc is a file format specified on top of the [Zstandard Compression Format][Zstd Format], at this time version 0.4.0.

Zarc is a toy file format: it has not been designed by archive format experts, has received no review, and only has a single implementation.

Zarc is intended to be fairly simple to parse given a zstd decoder, while providing some interesting features, like:

- always-on strong hashing and integrity verification;
- automatic per-archive "keyless" signing;
- full support for extended attributes (xattrs);
- high resolution timestamps;
- user-provided metadata at both archive and file level;
- basic deduplication via content-addressing;
- minimal uncompressed overhead;
- appending files is reasonably cheap;
- capable of handling archives larger than memory, or even archives containing more file metadata than would fit in memory (allowed by spec but not yet implemented).

## Known issues / limitations

- There's an uncompressed overhead per unique file, so if you have a lot of small files, it can be less efficient compared to tar+zstd which may squash the per-file overhead as well as the file content.

# [Zstd Format]

[Zstd Format]: https://github.com/facebook/zstd/blob/7cf62bc274105f5332bf2d28c57cb6e5669da4d8/doc/zstd_compression_format.md

Here's a quick recap of the zstd format, full specification available at link above:

- The format is a sequence of frames
- Frames can either be Zstandard frames or Skippable frames
- A standard zstd decoder will skip Skippable frames
- Numbers are little-endian
- Zstandard frames:
  - `[magic][header][blocks...][checksum]`
  - Magic is 0xFD2FB528
  - Header is 2-14 bytes, described in spec above
  - Checksum is optional, last 4 bytes of xxhash64
  - Blocks are:
    - `[size][type][last][data]`
      - Size is 21 bits, unsigned
      - Type is 2 bits (enum)
      - Last is 1 bit (boolean)
    - Type describes:
      1. Raw block (`data` is uncompressed, verbatim)
      2. RLE block (`data` is a single byte, `size` is how many times it's repeated verbatim)
      3. Compressed block
      4. Reserved
- Skippable frames:
  - `[magic][size][data]`
  - Magic is 0x184D2A5? where the last nibble **?** is any value from 0 to F
  - Size is unsigned 32-bit int

# Magic

The Zarc magic number is 0xDCAA65 in little-endian.

It is the string `Zarc` *de*coded as Base64:

```console
$ echo -n 'Zarc' | base64 -d | hexyl -p
65 aa dc
```

# Format

A Zarc is a defined sequence of zstd frames.

## Zarc Header

This is a Skippable frame with magic nibble = 0.

It contains:

| **`Zarc_Magic`** | **`Zarc_File_Version`** |
|:-:|:-:|
| 3 bytes | 1 byte |

This combined with the Skippable frame header, makes a Zarc file always start with the same 12 bytes:

| **`Zstd_Magic`** | **`Frame_Size`** | **`Zarc_Magic`** | **`Zarc_File_Version`** |
|:-:|:-:|:-:|:-:|
| 4 bytes | 4 bytes | 3 bytes | 1 byte |
| 0x184D2A50 | 0x00000004 | 0xDCAA65 | 0x01 |

## Zarc Unintended Magic

This is a Zstandard frame.

It contains:

- A Raw block containing four bytes, identical to the Zarc Header payload;
- A RLE block with a size of zero and a null byte as payload;
- An optional compressed block containing UTF-8 text.

The text may be something like:

> STOP! THIS IS A ZARC ARCHIVE THAT HAS BEEN UNCOMPRESSED WITH RAW ZSTD
>
> See https://github.com/passcod/zarc to unpack correctly.

This is intended to be consumed by Zstd decoders, which will either:

- choke on the zero-byte RLE, or
- add a human-readable header to the decompressed output which explains to the user why they got nonsense

A Zarc decoder SHOULD check that the first block contains the same magic and version as the Zarc Header, and then MUST discard the frame.

## Compressed File Content

These are zero or more Zstandard frames, containing actual file content.

## Zarc Directory Header

This is a Skippable frame with magic nibble = F.

It contains:

| **`Zarc_Magic`** | **`Zarc_File_Version`** | **`Zarc_Directory_Hash_Length`** | **`Zarc_Directory_Hash`** | **`Zarc_Directory_Sig_Length`** | **`Zarc_Directory_Sig`** | **`Zarc_Directory_Uncompressed_Length`** |
|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| 3 bytes | 1 byte | 2 bytes | `Zarc_Directory_Hash_Length` bytes | 2 bytes | `Zarc_Directory_Sig_Length` bytes | 8 bytes |

### `Zarc_Magic` and `Zarc_File_Version`

These must be the same as the values in the Zarc Header.

### `Zarc_Directory_Hash` (length-prefixed)

This is the digest of the directory contents.
The algorithm of the digest is defined in the directory structure.

### `Zarc_Directory_Sig` (length-prefixed)

This is a signature computed over the `Zarc_Directory_Hash` digest.
The algorithm and public key of the signature are defined in the directory structure.

### `Zarc_Directory_Uncompressed_Length`

This is the uncompressed length of the Zarc Directory structure.

This SHOULD be used to decide whether to decompress the directory in memory or stream it.

A directory that is not this exact length MUST be considered corrupt.

## Zarc Directory

This is a Zstandard frame.

It contains a [msgpack](https://msgpack.org)-encoded structure.
The top level is a map. Element order is insignificant _except_ that the first four items MUST be `v`, `h`, `s`, `k` (in any order).

Implementations MUST ignore keys they do not recognise.

### `v`: Zarc Directory Version

_Integer._ **Mandatory.**

This must be the value `1`.

### `h`: Hash Algorithm

_String._ **Mandatory.**

This MUST be one of the following values:

- `b3`: [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) hash function.

Implementations MAY offer an optional "insecure" mode which ignores hash mismatches or unknown algorithms.

### `s`: Signature Algorithm

_String._ **Mandatory.**

This MUST be one of the following values:

- `ed25519`: [Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519) signature scheme.

Implementations MAY offer an optional "insecure" mode which ignores signature mismatches or unknown algorithms.

### `k`: Signature Public Key

_Binary._ **Mandatory.**

Public key for the selected signature scheme.

### `u`: User Metadata

_Map._ **Optional.**

Arbitrary user-provided metadata for the whole Zarc file.

### `m`: Filemap

_Array._ **Mandatory.**

Each item contains:

#### `h`: Hash of Frame

_Binary._ **Conditional.**

The hash of a frame of content.
This must be the same value as the `h` field of a **Framelist** item.

Multiple files can reference the same content frame: this provides file-level deduplication.

The algorithm of the hash is described by the **Hash Algorithm** field above.

This may be absent for some special files (described later).

#### `n`: Name

_Array of Raw._ **Mandatory.**

If items are of the UTF-8 _String_ msgpack type, then they represent UTF-8-encoded Unicode pathname components.
If items are of the _Binary_ msgpack type instead, then they represent raw (non-Unicode) pathname components.

Non-Unicode pathnames may not be supported on all filesystems / operating systems.

Zarc makes no effort to restrict valid pathnames.
The exception is that the components `.` and `..` are disallowed.
A Zarc decoder MUST reject such pathnames.

Pathnames are encoded in components.
That is, the Unix pathname `foo/bar/baz.qux` and the Windows pathname `foo\bar\baz.qux` are encoded the same way.
Pathnames can mix UTF-8 and non-Unicode components.

Pathnames do not include drive letters or fileshare prefixes.
(It is not possible to construct a Zarc archive spanning multiple Windows drives.)

Pathnames do not encode whether a path is absolute or relative: all paths inside a Zarc archive are relative to an arbitrary root provided by the user when packing or unpacking.

It is possible to have several identical pathname in a Zarc Directory.
Implementations SHOULD provide an option to use the first or last or other selection criteria, but MUST default to preferring the last of a set of identical pathnames.

#### `u`: File User Metadata

_Map._ **Optional.**

Arbitrary user-provided metadata for this file entry.

#### `r`: File Is Readonly

_Boolean._ **Optional.**

If `true`, the file is marked read-only.

This is a filesystem mode only and has no bearing on Zarc's handling.

#### `m`: POSIX File Mode

_Integer._ **Optional.**

Unix mode bits as an unsigned 32-bit integer.

If this is not set, implementations SHOULD use a default mode as appropriate.

#### `o`: POSIX File Owner

_Map._ **Optional.**

The user that owns this file.
This is a structure with at least one of:

- `i`: _Integer._ the user ID
- `n`: _String._ the user name

Implementations SHOULD prefer the name to the ID if there is an existing user named thus on the system with a different ID.

#### `g`: POSIX File Group

_Map._ **Optional.**

The group that owns this file.
This is a structure with at least one of:

- `i`: _Integer._ the group ID
- `n`: _String._ the group name

Implementations SHOULD prefer the name to the ID if there is an existing group named thus on the system with a different ID.

#### `a`: POSIX File Attributes

_Map._ **Optional.**

A map of values (typically boolean flags) which keys SHOULD correspond to [file attributes](https://en.wikipedia.org/wiki/Chattr).

Implementations MAY ignore attributes if obtaining or setting them is impossible or impractical.

#### `x`: Extended File Attributes

_Map._ **Optional.**

A map of extended attributes (`xattr`).

Zarc imposes no restriction on the format of attribute names, nor on the content, type, nor length of attribute values.

Implementations MAY ignore extended attributes if obtaining or setting them is impossible or impractical.
On Linux, implementations MAY assume a `user` namespace for unprefixed keys.

#### `t`: File Timestamps

_Map of Timestamp._ **Optional.**

Timestamps associated with this file. Any of:

- `c`: ctime or file creation time
- `m`: mtime or file modification time
- `a`: atime or file access time — this SHOULD be the access time prior to the Zarc tool reading the file
- `z`: time the file was stored in this Zarc

Timestamps are stored in the [native msgpack Timestamp extension type](https://github.com/msgpack/msgpack/blob/master/spec.md#timestamp-extension-type).
They may be in any of the 32-bit (unsigned seconds since epoch), 64-bit (unsigned seconds + nanoseconds since epoch), or 96-bit (signed seconds + nanoseconds) precisions.

Encoding implementations SHOULD map timestamp precision to the highest available from the filesystem.
Decoding implementations MAY truncate precision to what is practicable for the filesystem.

#### `z`: Special File Types

_Map._ **Optional.**

This is a structure which encodes special file types.

Implementations SHOULD ignore unknown or impractical special types.

- `t`: _Integer._ **Mandatory.** Any of:
  - `0x00` — not needed: normal file.
  - `0x01` — directory entry.
    May be used to encode metadata or (x)attributes against a directory.
  - `0x1?` — link.
  - `0x10` — internal hardlink.
    MUST have a `d` field with the pathname of another file contained in this Zarc.
    MAY have the `h` field in the file entry pointing to the same contents.
  - `0x11` — external hardlink.
    MUST have a `d` field with the absolute pathname of a file to hardlink to.
    Implementations MAY reject this (e.g. for security reasons).
  - `0x12` — internal symlink.
    MUST have a `d` field with the pathname of another file contained in this Zarc.
  - `0x13` — external absolute symlink.
    MUST have a `d` field with the absolute pathname of a file to symlink to.
    Implementations MAY reject this (e.g. for security reasons).
  - `0x14` — external relative symlink.
    MUST have a `d` field with the relative pathname of a file to symlink to.
    Implementations MAY reject this (e.g. for security reasons).

- `d`: _Raw or Array of Raw_. **Conditional.** Destination pathname for links. Either an absolute or relative full pathname with platform-specific separators, or an array of components as described earlier. Unlike the Name field, `.` and `..` components are allowed.

### `l`: Framelist

_Array._ **Mandatory.**

Each item contains:

#### `o`: Frame Offset

_Integer._ **Mandatory.**

The offset in bytes from the start of the Zarc file to the first byte of the Zstandard frame header this entry describes.

There MUST NOT be duplicate Frame Offsets in the Framelist.

#### `n`: Uncompressed Byte Length

_Integer._ **Mandatory.**

The length of the uncompressed content of the frame in bytes.

Implementations MAY use this to avoid unpacking frames which exceed available memory or storage.

#### `h`: Frame Content Hash

_Binary._ **Mandatory.**

The digest of the frame contents using the algorithm defined at the top level.

Implementations MUST check that frame contents match this digest (unless "insecure" mode is used).

#### `s`: Frame Content Signature

_Binary._ **Mandatory.**

A signature computed over the Frame Content Hash using the algorithm defined at the top level.

Implementations MUST check that the signature is valid (unless "insecure" mode is used).

## Zarc EOF Trailer

This is a Skippable frame with magic nibble = E.

It contains:

| **`Zarc_Directory_Framed_Length`** |
|:-:|
| 8 bytes |

The length of the previous two frames (Zarc Directory Header and Zarc Directory) in bytes.

That is, the offset of the first byte of the Zarc Directory Header's Skippable Frame from the first byte of this frame (or 16 bytes from the end of the file).

# Decoding

1. Check the first 12 bytes match the Zarc Header
    - Alternatively, decode the first frame, check it is a Skippable frame with nibble = 0, and check magic and version numbers.
2. Check the Zarc Unintended Magic
    - Check raw block matches magic and version from Zarc Header
    - Ignore/discard the rest of the frame
3. Read 16 bytes from EOF
    - Decode as Skippable frame
    - Match nibble = E
    - Read LE u64 as Directory Offset
4. Read Zarc Directory Header at EOF - 16 - Directory Offset
    - Check for magic and version match
    - Collect hash and signature
    - Collect uncompressed directory length
5. Uncompress Zarc Directory
    - If not enough memory is available, do next steps streaming instead
6. Read first four fields of msgpack, then stop
    - Check they are `v`, `h`, `s`, `k` (in any order)
    - Verify version
    - Initialise cryptography
    - Verify digest against signature
    - Verify directory integrity against digest
    - If a Signed Attestation is given by the user, verify that also
7. Build a Frame Lookup Table
    - For each item in **Framelist**:
    - Verify frame digest against frame signature
    - Insert into hashtable k=Hash, v=(Offset, Size)
8. Read and extract files from **Filemap** as required.

# Appending

Zarc is designed so that more content may be appended without rebuilding the entire file.

1. Read original Zarc Directory (and Header)
2. Create a new keypair
3. Insert data frames as needed
4. Recompute all signatures
5. Insert **Framelist** entries as needed
6. Insert **Filemap** entries as needed
7. Write new directory and trailer

