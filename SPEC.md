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

| **`Magic`** | **`File Version`** |
|:-----------:|:------------------:|
|   3 bytes   |       1 byte       |
|  `65 aa dc` |        `01`        |

This combined with the Skippable frame header, makes a Zarc file always start with the same 12 bytes:

| **`Zstd Magic`** | **`Frame Size`** | **`Zarc Magic`** | **`Zarc File Version`** |
|:----------------:|:----------------:|:----------------:|:-----------------------:|
|      4 bytes     |      4 bytes     |     3 bytes      |          1 byte         |
|   `50 2a 4d 18`  |   `04 00 00 00`  |    `65 aa dc`    |           `01`          |

## Compressed File Content

These are zero or more Zstandard frames, containing actual file content.

## Zarc Directory

This is a Zstandard frame.

It contains a stream of [CBOR](https://cbor.io)-encoded Elements, which are framed with a Kind and a length.

| **`Kind`** | **`Length of Payload`** | _reserved_ | **`Payload`** |
|:----------:|:-----------------------:|:----------:|:-------------:|
|    LE U8   |         LE U16          |   1 byte   |      CBOR     |

Element Kinds are described below, along with their integer and CBOR payload structure.
Elements of a same Kind are NOT required to be next to each other.
Order is insignificant unless stated.

Implementations MUST ignore Element Kinds they do not recognise.

> **Non-normative note:** the _reserved_ byte is there mainly for possible expansion of the payload length.
> 64K per element looks pretty large from here, but who knows what the future brings.

### Kind `1`: Editions

_Map: unsigned integer keys -> CBOR._

Editions record core metadata about an archive, and also provide a mechanism for retaining the metadata of _previous versions_ of the archive, if it gets appended or edited.
At least one edition must be present.

#### Key `0`: Number

_Non-zero unsigned integer._ **Mandatory.**

The number of editions in a file is technically unlimited, but as of this version MUST be less than 65536.
For practical purposes implementations SHOULD warn when creating more than 1000 editions, and MAY set that limit lower.

Creating an edition involves incrementing the edition number, so the latest edition of the file is `max(edition list)`.

This is used in Frame and File types as the `Edition` field.

#### Key `1`: Public Key

_Byte string._ **Mandatory.**

The public key of this edition.

This can be used as a more unique ID than the edition number.

#### Key `2`: Written At

_Timestamp or DateTime._ **Mandatory.**

When this version was created.

#### Key `3`: Digest Type

_8-bit unsigned integer._ **Mandatory.**

Same as the Trailer value, the digest type in use by that edition.

#### Key `4`: Signature Type

_8-bit unsigned integer._ **Mandatory.**

Same as the Trailer value, the signature (and public key) type in use by that edition.

#### Key `10`: User Metadata

_Map: text string keys -> boolean or text or byte string._ **Optional.**

User metadata of this edition.

### Kind `2`: Files

_Map: unsigned integer keys -> CBOR._

#### Key `0`: Edition

_Unsigned integer._ **Mandatory.**

The edition this file entry was added to the archive.

#### Key `1`: Name

_Array of: text string or byte string._ **Mandatory.**

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

#### Key `2`: Frame Digest

_Byte string._ **Conditional.**

The hash of a frame of content.
This must be the same value as the `h` field of a **Framelist** item.

Multiple files can reference the same content frame: this provides file-level deduplication.

The algorithm of the hash is described by the **Hash Algorithm** field above.

This may be absent for some special files (described later).

#### Key `3`: POSIX File Mode

_Unsigned integer._ **Optional.**

Unix mode bits as an unsigned 32-bit integer.

If this is not set, implementations SHOULD use a default mode as appropriate.

#### Key `4`: POSIX File Owner

_Tuple (encoded as an array)._ **Optional.**

The user that owns this file.
This is a structure with at least one of the following types of data:

- _Unsigned integer._ the user ID
- _Text string._ the user name as UTF-8 (or ASCII)

There SHOULD NOT be more than one unsigned integer; if there are, the last value wins out.

Implementations SHOULD prefer the name to the ID if there is an existing user named thus on the system with a different ID.
Implementations SHOULD prefer to encode IDs as 32-bit unsigned integers, but MUST accept 8-bit, 16-bit, and 64-bit unsigned integers as well.

#### Key `5`: POSIX File Group

_Tuple (encoded as an array)._ **Optional.**

The group that owns this file.
This is a structure with at least one of the following types of data:

- _Unsigned integer._ the group ID
- _Text string._ the group name as UTF-8 (or ASCII)

Implementations SHOULD prefer the name to the ID if there is an existing group named thus on the system with a different ID.

#### Key `6`: File Timestamps

_Map: unsigned integer keys -> timestamp._ **Optional.**

Timestamps associated with this file. Any of:

- `1`: birth time or file creation time
- `2`: mtime or file modification time
- `3`: atime or file access time — this SHOULD be the access time prior to the Zarc tool reading the file

Timestamps can be stored in either:
- [RFC3339 in _text string_ with semantic tag `0`](https://www.rfc-editor.org/rfc/rfc8949.html#name-standard-date-time-string)
- [seconds from epoch as unsigned or negative integer, or binary64 floating point, with semantic tag `1`](https://www.rfc-editor.org/rfc/rfc8949.html#name-epoch-based-date-time)

> **Non-normative implementation note:** the Zarc reference implementation _accepts_ all formats for a timestamp, but always _writes_ RFC3339 text string datetimes.

#### Key `7`: Special File Types

_Pair: [unsigned integer, (pathname)?]._ **Optional.**

This is a structure which encodes special file types.

The mandatory first array item is the type of the special file.
Implementations SHOULD ignore unknown or impractical special types.

  - `1` — **directory entry.**
    May be used to encode metadata or (x)attributes against a directory.

  - `10` — **unspecified symlink.**
    MUST be followed by the pathname of the link target.
    - `11` — **internal symlink.**
      MUST be followed by the pathname of another file contained in this Zarc.
    - `12` — **external absolute symlink.**
      MUST be followed by the absolute pathname of a file to symlink to.
      Implementations MAY reject this (e.g. for security reasons).
    - `13` — **external relative symlink.**
      MUST be followed by the relative pathname of a file to symlink to.
      Implementations MAY reject this (e.g. for security reasons).

  - `20` — **unspecified hardlink.**
    MUST be followed by the pathname of another file contained in this Zarc.
    - `21` — **internal hardlink.**
      MUST be followed by the pathname of another file contained in this Zarc.
    - `22` — **external hardlink.**
      MUST be followed by the absolute pathname of a file to hardlink to.
      Implementations MAY reject this (e.g. for security reasons).

Pathnames (as the conditional second array item) are either:
- _Byte string_ or _Text string_. An absolute or relative full pathname with platform-specific separators;
- _Array(byte or text string)._ An array of components as for Filemap Names, except that `.` and `..` components are allowed.

The second form is preferred, for portability.

#### Key `10`: File User Metadata

_Map: text string keys -> boolean or text or byte string._ **Optional.**

Arbitrary user-provided metadata for this file entry.

#### Key `11`: File Attributes

_Map: text string keys -> boolean or text or byte string._ **Optional.**

A map of values (typically boolean flags) which keys SHOULD correspond to [file attributes](https://en.wikipedia.org/wiki/Chattr).

Implementations MAY ignore attributes if obtaining or setting them is impossible or impractical.

Attribute keys MUST either have a prefix signifying the system they apply to:

- `win32.` for Windows
- `linux.` for Linux
- `bsd.` for BSDs, including MacOS
- `_` for implementation-defined prefixes (e.g. `_ncc1701.`)

OR be one of these defined unprefixed values:

- `append-only`
- `compressed`
- `immutable`
- `read-only`

> **Note:** attributes are metadata only, they have no bearing on the Zarc file format semantics.

#### Key `12`: Extended File Attributes

_Map: text string keys -> boolean or text or byte string._ **Optional.**

A map of extended attributes (`xattr`).

Zarc imposes no restriction on the format of attribute names, nor on the content or length of attribute values.

Implementations MAY ignore extended attributes if obtaining or setting them is impossible or impractical.
On Linux, implementations MAY assume a `user` namespace for unprefixed keys.

### Kind `3`: Frames

_Map: unsigned integer keys -> CBOR._ **Mandatory, collect-up.**

Structures of this type SHOULD appear in offset order.

#### Key `0`: Edition Added

_Unsigned integer._ **Mandatory.**

The edition this frame was added to the archive.

#### Key `1`: Frame Offset

_Integer._ **Mandatory.**

The offset in bytes from the start of the Zarc file to the first byte of the Zstandard frame header this entry describes.

There MUST NOT be duplicate Frame Offsets in the Frame list.

#### Key `2`: Frame Content Digest

_Byte string._ **Mandatory.**

The digest of the frame contents.

Implementations MUST check that frame contents match this digest (unless "insecure" mode is used).

#### Key `3`: Frame Content Signature

_Byte string._ **Mandatory.**

A signature computed over the Frame Content Hash.

Implementations MUST check that the signature is valid (unless "insecure" mode is used).

#### Key `4`: Framed Size

_Integer._ **Mandatory.**

The size of the entire frame in bytes.

This may be used to request that range of bytes from a remote source without reading too far or incrementally via block information.

#### Key `5`: Uncompressed Content Length

_Integer._ **Mandatory.**

The length of the uncompressed content of the frame in bytes.

This is a complement to the Frame Content Size field available on the Zstandard Frame directly, as that field can be absent depending on zstd parameters.

This can be used to e.g.:
- avoid unpacking frames which exceed available memory or storage;
- preallocate storage before unpacking;
- estimate the uncompressed total size of the archive.

## Zarc Trailer

This is a Skippable frame with magic nibble = F.

It contains:

| **`Public Key`** | **`Digest`**| **`Signature`** |
|:----------------:|:-----------:|:---------------:|
|     _n_ bytes    |  _n_ bytes  |    _n_ bytes    |

| **`Check Byte`** | **`Digest Type`** | **`Signature Type`** |
|:----------------:|:-----------------:|:--------------------:|
|      1 byte      |       1 byte      |        1 byte        |

|   **`Directory Offset`**  | **`Uncompressed Length`** |
|:-------------------------:|:-------------------------:|
|           8 bytes         |           8 bytes         |

| **`Directory Version`** | **`File Version`** | **`Magic`** |
|:-----------------------:|:------------------:|:-----------:|
|          1 byte         |       1 byte       |   3 bytes   |
|           `01`          |        `01`        |  `65 aa dc` |

> **Non-normative implementation note:** This looks upside down, because you read it from the end.
> The last three bytes of a Zarc file will always be `65 aa dc`, _preceded_ by the file version, _preceded_ by the directory version, etc.
> The fixed-width fields are all at the end, so they can be read by seeking to a fixed offset from the end.
> The `Digest Type` and `Signature Type` are then used to derive the lengths of the variable fields.
> Going 8 bytes further back will yield the Zstd Skippable frame header if you so wish to check that.

### `Magic` and `File Version`

These MUST be the same as the values in the Zarc Header.

### `Directory Version`

This MUST be `1`.

### `Directory Offset`

_Signed 64-bit integer._

This is EITHER:

- a **positive** value, the offset from the **start** of the file to the first byte of the Zstandard frame containing the Zarc Directory.
- a **negative** value, the offset from the **end**   of the file to the first byte of the Zstandard frame containing the Zarc Directory.

### `Uncompressed Length`

This is the uncompressed length of the Zarc Directory structure.

This may be used to decide whether to decompress the directory in memory or stream it.

### `Digest Type`

Defines the algorithm used for computing digests, as well as the length of the digest fields:

- `0`: not used. This value must not appear.
- `1`: [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) hash function, 32-byte digests.

### `Signature Type`

Defines the algorithm used for computing signatures, as well as the length of the public key and signature fields:

- `0`: not used. This value must not appear.
- `1`: [Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519) signature scheme, 32-byte public key, 64-byte signature.

### `Check Byte`

This is the result of XOR'ing every other byte of the trailer together.

It can be used as a quick check for corruption.
