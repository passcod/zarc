# Introduction

Zarc is a file format specified on top of the [Zstandard Compression Format][Zstd Format], at this time version 0.4.0.

Zarc is a toy file format: it has received no review, only has a single implementation, and is not considered mature enough for serious use.

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

**CAUTION:** the format is currently unstable and changes without version bump or notice.

# [Zstd Format]

[Zstd Format]: https://datatracker.ietf.org/doc/html/rfc8878

Here's a quick recap of the zstd format:

- The format is a sequence of frames
- Frames can either be Zstandard frames or Skippable frames
- A standard zstd decoder will skip Skippable frames
- Numbers are little-endian
- Zstandard frames:
  - `[magic][header][blocks...][checksum]`
  - Magic is 0xFD2FB528
  - Header is 2-14 bytes, described in spec
  - Checksum is optional, last 4 bytes of xxhash64
  - Blocks are:
    - `[last][type][size][data]`
      - Last is 1 bit (boolean)
      - Type is 2 bits (enum)
      - Size is 21 bits, unsigned
    - Type describes:
      0. Raw block (`data` is uncompressed, verbatim)
      1. RLE block (`data` is a single byte, `size` is how many times it's repeated verbatim)
      2. Compressed block
      3. Reserved
- Skippable frames:
  - `[magic][size][data]`
  - Magic is 0x184D2A5? where the last nibble **?** is any value from 0 to F
  - Size is unsigned 32-bit int

Further reading:
- Informational RFC8878: <https://datatracker.ietf.org/doc/html/rfc8878>
- Most up-to-date spec: <https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md>

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

It contains a [CBOR](https://cbor.io)-encoded structure.
The top level is a map with unsigned integer keys. Element order is insignificant _except_ that the first four items MUST be `0` through `3` (in any order).

Implementations MUST ignore keys they do not recognise.

### `0`: Zarc Directory Version

_Integer._ **Mandatory.**

This must be the value `1`.

### `1`: Hash Algorithm

_Integer._ **Mandatory.**

This MUST be one of the following values:

- `0`: not used. This value must not appear.
- `1`: [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) hash function.

Implementations MAY offer an optional "insecure" mode which ignores hash mismatches or unknown algorithms.

### `2`: Signature Algorithm

_Integer._ **Mandatory.**

This MUST be one of the following values:

- `0`: not used. This value must not appear.
- `1`: [Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519) signature scheme.

Implementations MAY offer an optional "insecure" mode which ignores signature mismatches or unknown algorithms.

### `3`: Signature Public Key

_Byte string._ **Mandatory.**

Public key for the selected signature scheme.

#### `4`: Written At

_Timestamp or DateTime._ **Mandatory.**

When this archive was created.

### `10`: User Metadata

_Map(text string, boolean or text or byte string)._ **Optional.**

Arbitrary user-provided metadata for the whole Zarc file.

### `13`: Prior Versions

_Array of maps._ **Optional.**

If this archive was appended to, this contains metadata for the previous versions of the directory.
Entries are in reverse-chronological order, with the most recent prior version first.

A maximum of 65536 prior versions can be stored, though for practical purposes implementations SHOULD restrict this to a much lower number when packing.

#### `0`: Zarc Directory Version

_Integer._ **Optional.**

Version of the directory if the current version is different from this one.

#### `1`: Hash Algorithm

_Integer._ **Mandatory.**

Hash algorithm (see above for list) of this version.

#### `2`: Signature Algorithm

_Integer._ **Mandatory.**

Signature algorithm (see above for list) of this version.

#### `3`: Signature Public Key

_Byte string._ **Mandatory.**

Public key of this version.

#### `4`: Written At

_Timestamp or DateTime._ **Mandatory.**

When this version was created.

#### `10`: User Metadata

_Map(text string, boolean or text or byte string)._ **Optional.**

User metadata of this version.

### `20`: Filemap

_Array of maps._ **Mandatory.**

Each item contains:

#### `0`: Name

_Array of Raw._ **Mandatory.**

If items are of the UTF-8 _Text string_ CBOR type, then they represent UTF-8-encoded Unicode pathname components.
If items are of the _Byte string_ CBOR type instead, then they represent raw (non-Unicode) pathname components.

Windows implementations MUST convert raw UTF-16 to UTF-8 during encoding, and from raw bytes to UTF-8 during decoding, and replace invalid wide character sequences with the Unicode REPLACEMENT CHARACTER.

Non-Unicode pathnames may not be supported on all filesystems / operating systems.
Implementations SHOULD strongly prefer UTF-8, and SHOULD warn when paths do not convert cleanly.

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

#### `1`: Hash of Frame

_Binary._ **Conditional.**

The hash of a frame of content.
This must be the same value as the `h` field of a **Framelist** item.

Multiple files can reference the same content frame: this provides file-level deduplication.

The algorithm of the hash is described by the **Hash Algorithm** field above.

This may be absent for some special files (described later).

#### `2`: File Is Readonly

_Boolean._ **Optional.**

If `true`, the file is marked read-only.

This is a filesystem mode only and has no bearing on Zarc's handling.

#### `3`: POSIX File Mode

_Unsigned integer._ **Optional.**

Unix mode bits as an unsigned 32-bit integer.

If this is not set, implementations SHOULD use a default mode as appropriate.

#### `4`: POSIX File Owner

_Array._ **Optional.**

The user that owns this file.
This is a structure with at least one of the following types of data:

- _Unsigned integer._ the user ID
- _Text string._ the user name as UTF-8
- _Byte string._ the user name as non-Unicode

There SHOULD NOT be both _Text string_ and _Byte string_ values; if there are, the _Text string_ value wins out.
There SHOULD NOT be more than one unsigned integer; if there are, the last value wins out.

Implementations SHOULD prefer the name to the ID if there is an existing user named thus on the system with a different ID.
Implementations SHOULD prefer to encode IDs as 32-bit unsigned integers, but MUST accept 8-bit, 16-bit, and 64-bit unsigned integers as well.

#### `5`: POSIX File Group

_Array._ **Optional.**

The group that owns this file.
This is a structure with at least one of the following types of data:

- _Unsigned integer._ the group ID
- _Text string._ the group name as UTF-8
- _Byte string._ the group name as non-Unicode

There SHOULD NOT be both _Text string_ and _Byte string_ values. If there is, the _Text string_ value wins out.

Implementations SHOULD prefer the name to the ID if there is an existing group named thus on the system with a different ID.

#### `10`: File User Metadata

_Map(text string, boolean or text or byte string)._ **Optional.**

Arbitrary user-provided metadata for this file entry.

#### `11`: File Attributes

_Map(text string, boolean or text or byte string)._ **Optional.**

A map of values (typically boolean flags) which keys SHOULD correspond to [file attributes](https://en.wikipedia.org/wiki/Chattr).

Implementations MAY ignore attributes if obtaining or setting them is impossible or impractical.

#### `12`: Extended File Attributes

_Map(text string, boolean or text or byte string)._ **Optional.**

A map of extended attributes (`xattr`).

Zarc imposes no restriction on the format of attribute names, nor on the content or length of attribute values.

Implementations MAY ignore extended attributes if obtaining or setting them is impossible or impractical.
On Linux, implementations MAY assume a `user` namespace for unprefixed keys.

#### `13`: Version Added

_Integer._ **Optional.**

If this file entry was added by another version than current, this is the index of that version.

#### `20`: File Timestamps

_Map(unsigned integer, timestamp)._ **Optional.**

Timestamps associated with this file. Any of:

- `0`: time the file was stored in this Zarc
- `1`: ctime or file creation time
- `2`: mtime or file modification time
- `3`: atime or file access time — this SHOULD be the access time prior to the Zarc tool reading the file

Timestamps can be stored in either:
- [RFC3339 in _text string_ with semantic tag `0`](https://www.rfc-editor.org/rfc/rfc8949.html#name-standard-date-time-string)
- [seconds from epoch as unsigned or negative integer, or binary64 floating point, with semantic tag `1`](https://www.rfc-editor.org/rfc/rfc8949.html#name-epoch-based-date-time)

#### `30`: Special File Types

_Array[unsigned integer, ...CBOR]._ **Optional.**

This is a structure which encodes special file types.

The mandatory first array item is the type of the special file.
Implementations SHOULD ignore unknown or impractical special types.

  - `1` — directory entry.
    May be used to encode metadata or (x)attributes against a directory.
  - `10` — unspecified link.
    MUST be followed by the pathname of the link target.
    Implementations can interpret this however they see fit.
  - `11` — internal hardlink.
    MUST be followed by the pathname of another file contained in this Zarc.
  - `12` — external hardlink.
    MUST be followed by the absolute pathname of a file to hardlink to.
    Implementations MAY reject this (e.g. for security reasons).
  - `13` — internal symlink.
    MUST be followed by the pathname of another file contained in this Zarc.
  - `14` — external absolute symlink.
    MUST be followed by the absolute pathname of a file to symlink to.
    Implementations MAY reject this (e.g. for security reasons).
  - `15` — external relative symlink.
    MUST be followed by the relative pathname of a file to symlink to.
    Implementations MAY reject this (e.g. for security reasons).

Pathnames (as the conditional second array item) are either:
- _Byte string_ or _Text string_. An absolute or relative full pathname with platform-specific separators;
- _Array(byte or text string)._ An array of components as for Filemap Names, except that `.` and `..` components are allowed.

The second form is preferred, for portability.

### `21`: Framelist

_Array of maps._ **Mandatory.**

Items MUST appear in offset order.

Each item contains:

#### `0`: Frame Offset

_Integer._ **Mandatory.**

The offset in bytes from the start of the Zarc file to the first byte of the Zstandard frame header this entry describes.

There MUST NOT be duplicate Frame Offsets in the Framelist.

#### `1`: Frame Content Hash

_Binary._ **Mandatory.**

The digest of the frame contents using the algorithm defined at the top level.

Implementations MUST check that frame contents match this digest (unless "insecure" mode is used).

#### `2`: Frame Content Signature

_Binary._ **Mandatory.**

A signature computed over the Frame Content Hash using the algorithm defined at the top level.

Implementations MUST check that the signature is valid (unless "insecure" mode is used).

#### `3`: Uncompressed Content Length

_Integer._ **Mandatory.**

The length of the uncompressed content of the frame in bytes.

This is a complement to the Frame Content Size field available on the Zstandard Frame directly, as that field can be absent depending on zstd parameters.

This can be used to e.g.:
- avoid unpacking frames which exceed available memory or storage;
- to preallocate storage before unpacking;
- estimate the uncompressed total size of the archive.

#### `13`: Version Added

_Integer._ **Optional.**

If this frame was added by another version than current, this is the index of that version.

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
6. Read first four fields of CBOR map, then stop
    - Check they are `0` through `3` (in any order)
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
3. Insert new **Prior Version** entry
4. Change all existing frames and filemaps to reference the old version
5. Insert new data frames as needed
6. Insert new **Framelist** entries as needed
7. Insert new **Filemap** entries as needed
8. On option, and if the hash algorithm has changed, recompute all hashes.
9. Recompute all signatures
10. Write new directory and trailer

