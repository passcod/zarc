# Zarc

Zarc is a new archive file format.
Think like `tar` or `zip`, not `gzip` or `xz`.

**Warning:**
Zarc is a toy: it has received no review, only has a single implementation, currently loads files entirely in memory, and generally has not been optimised.
Do not use for production data.

Zarc provides some interesting features, like:

- always-on strong hashing and integrity verification;
- automatic per-archive "keyless" signing;
- full support for extended attributes (xattrs);
- high resolution timestamps;
- user-provided metadata at both archive and file level;
- basic deduplication via content-addressing;
- minimal uncompressed overhead;
- appending files is reasonably cheap;
- capable of handling archives larger than memory, or even archives containing more file metadata than would fit in memory (allowed by spec but not yet implemented).

Here's a [specification](./SPEC.md) of the format.

## Try it out

### Install

This repository contains a Rust library crate implementing the format, and a Rust CLI tool.
You can install it using [a recent stable Rust](https://rustup.sh):

```console
$ cargo install zarc-cli
```

As this is in early development, you may prefer to install from the latest source instead:

```console
$ cargo install --git https://github.com/passcod/zarc zarc-cli
```

That installs the `zarc` CLI tool.

### Start out

Get started by packing a few files:

```console
$ zarc pack --output myfirst.zarc  a.file and folder
zarc public key: 4D0CYzSBrmO+BqSfkdXKiA/p4yXNwgl40slgVtUympI=

$ ls -lh myfirst.zarc
-rw-r--r-- 1 you you 16K Dec 30 01:34 myfirst.zarc

$ file myfirst.zarc
myfirst.zarc: Zstandard compressed data (v0.8+), Dictionary ID: None
```

Zarc creates files that are valid Zstd streams.
However, decompressing such a file with `zstd` will not yield your files back, as the file/tree metadata is skipped by `zstd`.
Instead, look inside with Zarc:

```console
$ zarc list-files myfirst.zarc
a.file
and/another.one
folder/thirdfile.here
folder/subfolder/a.file
folder/other/example.file
```

<details>
<summary>If you want to see everything a Zarc contains, use the debug tool:</summary>

```console
$ zarc debug myfirst.zarc
frame: 0
  magic: [50, 2a, 4d, 18] (skippable frame)
  nibble: 0x0
  length: 4 (0x00000004)
  zarc: header (file format v1)

frame: 1
  magic: [28, b5, 2f, fd] (zstandard frame)
  descriptor: 10001001 (0x89)
    single segment: true
    has checksum: false
    unused bit: false
    reserved bit: false
    fcs size flag: 0 (0b00)
      actual size: 1 bytes
    did size flag: 0 (0b00)
      actual size: 0 bytes
  uncompressed size: 137 bytes

...snip...

frame: 8
  magic: [28, b5, 2f, fd] (zstandard frame)
  descriptor: 11010111 (0xD7)
    single segment: true
    has checksum: true
    unused bit: false
    reserved bit: false
    fcs size flag: 1 (0b01)
      actual size: 2 bytes
    did size flag: 0 (0b00)
      actual size: 0 bytes
  uncompressed size: 55313 bytes
  checksum: 0x55C7DC15

  block: 0 (Compressed)
    size: 3083 bytes (0xC0B)

  zarc: directory (directory format v1) (4823 bytes)
    hash algorithm: Blake3
      directory digest: valid ✅
    signature scheme: Ed25519
    public key: xRME2Ip754MEcky6/v6mZEFACWuJwccHx+n+Xly3rDA=
      directory signature: valid ✅
    files: 5
      file 0: ZWPZswtyW69gw+VyEGyE2h3ClqK05Y6uJ545LFu3srM=
        path: (4 components)
          folder
          subfolder
          a.file
        readonly: false
        posix mode: 00100644 (rw-r--r--)
        posix user: id=1000
        posix group: id=1000
        timestamps:
          inserted: 2023-12-29 11:19:05.747182826 UTC
          created: 2023-12-29 04:14:52.160502712 UTC
          modified: 2023-12-29 07:22:13.457676519 UTC
          accessed: 2023-12-29 07:22:13.787676534 UTC

...snip...

    frames: 4
      frame 0: ZWPZswtyW69gw+VyEGyE2h3ClqK05Y6uJ545LFu3srM=
        offset: 151 bytes
        uncompressed size: 390 bytes
        signature: ZH0rKbvBrT6e+VhDtQzyXyC7RGXQ62IbzdVgEXmM6hFGen73dLrw2ohZc1pVhTUuTQ1vC338JFVHL9nr36CAAA== (✅)
      frame 1: pN1pVhJbe0vXIgf8VP7TvqquOJZTSUVYW7QEm0XdVdk=
        offset: 439 bytes
        uncompressed size: 13830 bytes
        signature: 6m3B+zzIxVOymme4+APplXWbv4z9iTzuB3eZoWmfDaeLnhw3Yu5s2+IUAPzrUtNPf+0mgPKjtjhZwlFLKw7wDw== (✅)
      frame 2: Thzfvpr+lCZCiXOxwuwtZr3mPXLf2tt1oVTSX/g3dpw=
        offset: 4528 bytes
        uncompressed size: 431 bytes

...snip...

frame: 9
  magic: [5e, 2a, 4d, 18] (skippable frame)
  nibble: 0xE
  length: 8 (0x00000008)
  zarc: eof trailer
    directory offset: 3233 bytes from end
```

`zarc debug` prints all the information it can, including low-level details from the underlying Zstandard streams.
You can use it against non-Zarc Zstandard files, too.
Try the `-d` (to print data sections), `-D` (to uncompress and print zstandard frames), and `-n 3` (to stop after N frames) options!

</details>

Then, to unpack:

```console
$ zarc unpack myfirst.zarc
5 files written
```

## Features

### File deduplication

Internally, a Zarc is a content-addressed store with a directory of file metadata.
If you have two copies of some identical file, Zarc stores the metadata for each copy, and one copy of the content.

### Always-on integrity

Zarc computes the cryptographic checksum of every file it packs, and verifies data when it unpacks.
It also stores and verifies the integrity of its directory using that same hash function.

Content integrity is per-file; if a Zarc is corrupted but its directory is still readable:
- you can see exactly which files are affected, and
- you can safely unpack intact files.

### Automatic keyless signing

Zarc generates a unique keypair every time it packs (or repacks) an archive, and signs every checksum.
It then prints the public key and discards the secret one.
That is used to further verify integrity.

You can generate an extra signature for external data with `--attest 'some content'`.
This will print the signature for this data, and you can use that to prove authorship or provenance,
or to hook into another PKI scheme.

### User metadata

Zarc already stores file attributes and extended attributes, and even stores directory and link metadata.
But if you want to store custom metadata, it has dedicated support too:

#### At the archive level

```console
$ zarc pack \
  -u Created-By "Félix Saparelli" \
  -u Rust-Version "$(rustc -Vv)" \
  --output meta.zarc  filelist
```

#### At the file level

```console
$ zarc pack \
  -U one.file Created-By "Félix Saparelli" \
  -U 'crates/*/glob' Rust-Version "$(rustc -Vv)" \
  --output meta.zarc  filelist
```

### Cheap appends

Adding more files to a Zarc is done without recreating the entire archive:

```console
$ zarc pack --append --output myfirst.zarc  more.files and/folders
```

If new content duplicates the existing, it won't store new copies.
If new files are added that have the same path as existing ones, both the new and old metadata are kept.
By default, Zarc will unpack the last version of a path, but you can change that.

Zarc stores the insertion date of files, so you can tell whether and when a file was appended.

Appending to a Zarc regenerates the keypair and re-signs every checksum, so the new archive can't be confused for the old.

### Limitations

- Compression is per unique file, so it won't achieve compression gains across similar-but-not-identical files.
- There's an uncompressed overhead per unique file, so if you have a lot of small _unique_ files, it can be less efficient compared to tar+zstd which may squash the per-file overhead as well as the file content.

