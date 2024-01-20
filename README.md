# Zarc

Zarc is a new archive file format.
Think like `tar` or `zip`, not `gzip` or `xz`.

**Warning:**
Zarc is a toy: it has received no review, only has a single implementation, currently loads files entirely in memory, and generally has not been optimised.
Do not use for production data.

Zarc provides some interesting features, like:

- always-on strong hashing and integrity verification;
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
You can install it using [a recent stable Rust](https://rustup.rs):

```console
$ cargo install --git https://github.com/passcod/zarc zarc-cli
```

That installs the `zarc` CLI tool.

As we rely on an unreleased version of [deku](https://github.com/sharksforarms/deku), this isn't yet published on crates.io.

Alternatively, download binaries: <https://public.axodotdev.host/releases/github/passcod/zarc>

### Start out

_(Some of the commands shown here [don't exist yet](#todo).)_

Get started by packing a few files:

```console
$ zarc pack --output myfirst.zarc  a.file and folder

$ ls -lh myfirst.zarc
-rw-r--r-- 1 you you 16K Dec 30 01:34 myfirst.zarc

$ file myfirst.zarc
myfirst.zarc: Zstandard compressed data (v0.8+), Dictionary ID: None

$ zstd --test myfirst.zarc
myfirst.zarc        : 70392 bytes
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
      frame 1: pN1pVhJbe0vXIgf8VP7TvqquOJZTSUVYW7QEm0XdVdk=
        offset: 439 bytes
        uncompressed size: 13830 bytes
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
unpacked 5 files
```

## Features

### File deduplication

Internally, a Zarc is a content-addressed store with a directory of file metadata.
If you have two copies of some identical file, Zarc stores the metadata for each copy, and one copy of the content.

### Access to individual files

A major issue with Tar and Tar-based formats is that you can't extract a single file or list all the files in the archive without reading (and decompressing) the entire file.
Zarc's directory is read without reading nor decompressing the rest of the file, so listing files and metadata is always fast.
Zarc also stores offsets to file contents within the directory, so individual files can be efficiently unpacked.

### Always-on integrity

Zarc computes the cryptographic checksum of every file it packs, and verifies data when it unpacks.
It also stores and verifies the integrity of its directory using that same hash function.

You can verify integrity cheaply by comparing the digest of the directory only, instead of hashing the entire file.
For ease of use, external digest verification is built in the tool:

```console
$ zarc pack --output file.zarc folder/
digest: puKGv1aG1ANEq7wBxnrJbJ2OPcpBizcG+/sBM89G9fQ=

$ zarc unpack --verify puKGv1aG1ANEq7wBxnrJbJ2OPcpBizcG+/sBM89G9fQ= file.zarc
unpacked 32 files

$ time zarc unpack --verify qgsB/WyzVCcTH+DWnpUKnFTY22d7hpHewAyBvyv1SB8= file.zarc
Error:   × integrity failure: zarc file digest is puKGv1aG1ANEq7wBxnrJbJ2OPcpBizcG+/sBM89G9fQ=

Command exited with non-zero status 1
0.00user 0.00system 0:00.00elapsed 50%CPU (0avgtext+0avgdata 4536maxresident)k
0inputs+0outputs (0major+199minor)pagefaults 0swaps
```

Content integrity is per-file; if a Zarc is corrupted but its directory is still readable:
- you can see exactly which files are affected, and
- you can safely unpack intact files.

_(not yet implemented)_


### Universal paths

Paths are stored split into components, not as literal strings.
On Windows a path looks like `crates\\cli\\src\\pack.rs` and on Unix a path looks like `crates/cli/src/pack.rs`.
Instead of performing path translation, Zarc stores them as an array of components: `["crates", "cli", "src", "pack.rs"]`, so they get interpreted precisely and exactly the same on all platforms.
Of course, some paths aren't Unicode, and Zarc recognises that and stores non-UTF-8 components marked as bytestringsinstead of text.

### Attribute support

File and directory (and symlink etc) attributes and extended attributes are stored and restored as possible.
You'd think this wouldn't be a feature but hooo boy are many other formats inconsistent on this.

### User metadata

If you want to store custom metadata, there's dedicated support:

#### At the archive level
_(not yet implemented)_

```console
$ zarc pack \
  -u Created-By "Félix Saparelli" \
  -u Rust-Version "$(rustc -Vv)" \
  --output meta.zarc  filelist
```

#### At the file level
_(not yet implemented)_

```console
$ zarc pack \
  -U one.file Created-By "Félix Saparelli" \
  -U 'crates/*/glob' Rust-Version "$(rustc -Vv)" \
  --output meta.zarc  filelist
```

### Cheap appends
_(not yet implemented)_

Adding more files to a Zarc is done without recreating the entire archive:

```console
$ zarc pack --append --output myfirst.zarc  more.files and/folders
```

If new content duplicates the existing, it won't store new copies.
If new files are added that have the same path as existing ones, both the new and old metadata are kept.
By default, Zarc will unpack the last version of a path, but you can change that.

Appending to a Zarc keeps metadata about the prior versions for provenance.
Zarc stores the insertion date of files and the creation date of the archive itself as well as all prior versions, so you can tell whether a file was appended and when it was created or modified.

### Complexity and extensibility

Tar is considered to be quite complicated to parse, hard to extend, and implementations are frequently incompatible with each others in subtle ways.
A minor goal of Zarc is to [specify](./SPEC.md) a format that is relatively simple to parse, work with, and extend.

### Limitations

- Compression is per unique file, so it won't achieve compression gains across similar-but-not-identical files.

## Performance

In early testing, it's 2–4 times slower at packing than tar+zstd, but yields comparable (±10%) archive sizes.
It's 3–10 times _faster_ than Linux's zip, and yields consistently 10-30% smaller archives.

### a gigabyte of node\_modules

A Node.js's project `node_modules` is typically many small and medium files:

```console
$ tree node_modules | wc -l
172572

$ dust -sbn0 node_modules
907M ┌── node_modules

$ find node_modules -type f -printf '%s\\n' | datamash \
max 1           min 1   mean 1          median 1
20905472        0       6134.9564061426 822      # in bytes

$ find node_modules -type l | wc -l
812 # symlinks
```

#### Packing speed

```console
$ hyperfine --warmup 2 \
  --prepare 'rm node_modules.tar.zst || true' \
    'tar -caf node_modules.tar.zst node_modules' \
  --prepare 'rm node_modules.zip || true' \
    'zip -qr --symlinks node_modules.zip node_modules' \
  --prepare 'rm node_modules.zarc || true' \
    'zarc pack --output node_modules.zarc node_modules'

Benchmark 1: tar -caf node_modules.tar.zst node_modules
  Time (mean ± σ):      7.273 s ±  0.636 s    [User: 8.587 s, System: 3.395 s]
  Range (min … max):    5.806 s …  8.150 s    10 runs

Benchmark 2: zip -qr --symlinks node_modules.zip node_modules
  Time (mean ± σ):     47.042 s ±  2.102 s    [User: 40.272 s, System: 6.038 s]
  Range (min … max):   44.504 s … 49.788 s    10 runs

Benchmark 3: zarc pack --output node_modules.zarc node_modules
  Time (mean ± σ):     11.093 s ±  0.180 s    [User: 8.375 s, System: 2.552 s]
  Range (min … max):   10.873 s … 11.362 s    10 runs

Summary
  'tar -caf node_modules.tar.zst node_modules' ran
    1.53 ± 0.14 times faster than 'zarc pack --output node_modules.zarc node_modules'
    6.47 ± 0.64 times faster than 'zip -qr --symlinks node_modules.zip node_modules'
```

#### Archive size

```console
$ dust -sbn0 node_modules.tar.zst
189M ┌── node_modules.tar.zst

$ dust -sbn0 node_modules.zip
301M ┌── node_modules.zip

$ dust -sbn0 node_modules.zarc
209M ┌── node_modules.zarc
```

### node\_modules, following symlinks

That same workload, but following/dereferencing symlinks.

#### Packing speed

```console
$ hyperfine --warmup 2 \
  --prepare 'rm node_modules.tar.zst || true' \
    'tar -chaf node_modules.tar.zst node_modules' \
  --prepare 'rm node_modules.zip || true' \
    'zip -qr node_modules.zip node_modules' \
  --prepare 'rm node_modules.zarc || true' \
    'zarc pack -L --output node_modules.zarc node_modules'

Benchmark 1: tar -chaf node_modules.tar.zst node_modules
  Time (mean ± σ):     11.399 s ±  0.899 s    [User: 13.156 s, System: 4.591 s]
  Range (min … max):   10.369 s … 13.036 s    10 runs

Benchmark 2: zip -qr node_modules.zip node_modules
  Time (mean ± σ):     89.879 s ±  3.751 s    [User: 79.802 s, System: 8.216 s]
  Range (min … max):   84.980 s … 95.516 s    10 runs

Benchmark 3: zarc pack -L --output node_modules.zarc node_modules
  Time (mean ± σ):     16.526 s ±  0.380 s    [User: 12.961 s, System: 3.340 s]
  Range (min … max):   16.146 s … 17.515 s    10 runs

Summary
  'tar -chaf node_modules.tar.zst node_modules' ran
    1.45 ± 0.12 times faster than 'zarc pack -L --output node_modules.zarc node_modules'
    7.88 ± 0.70 times faster than 'zip -qr node_modules.zip node_modules'
```

#### Archive size

```console
$ dust -sbn0 node_modules.tar.zst
431M ┌── node_modules.tar.zst

$ dust -sbn0 node_modules.zip
595M ┌── node_modules.zip

$ dust -sbn0 node_modules.zarc
429M ┌── node_modules.zarc
```

### half a gig of ebooks

My personal collection of ebooks: few files, but relatively heavy and tough to compress more.

```console
$ tree ~/Documents/Ebooks | wc -l
54

$ dust -sbn0 ~/Documents/Ebooks
573M ┌── Ebooks

$ find ~/Documents/Ebooks -type f -printf '%s\\n' | datamash \
max 1           min 1   mean 1          median 1
247604768       15116   12028762.56     711323      # in bytes

$ find ~/Documents/Ebooks -type l | wc -l
0 # symlinks
```

#### Packing speed

```console
$ hyperfine --warmup 2 \
  --prepare 'rm ebooks.tar.zst || true' \
    'tar -caf ebooks.tar.zst ~/Documents/Ebooks' \
  --prepare 'rm ebooks.zip || true' \
    'zip -qr ebooks.zip ~/Documents/Ebooks' \
  --prepare 'rm ebooks.zarc || true' \
    'zarc pack -L --output ebooks.zarc ~/Documents/Ebooks'

Benchmark 1: tar -caf ebooks.tar.zst ~/Documents/Ebooks
  Time (mean ± σ):      2.133 s ±  0.168 s    [User: 2.421 s, System: 1.269 s]
  Range (min … max):    1.951 s …  2.502 s    10 runs

Benchmark 2: zip -qr ebooks.zip ~/Documents/Ebooks
  Time (mean ± σ):     23.859 s ±  1.274 s    [User: 22.202 s, System: 1.198 s]
  Range (min … max):   21.384 s … 25.397 s    10 runs

Benchmark 3: zarc pack -L --output ebooks.zarc ~/Documents/Ebooks
  Time (mean ± σ):      2.014 s ±  0.239 s    [User: 1.282 s, System: 0.671 s]
  Range (min … max):    1.835 s …  2.576 s    10 runs

Summary
  'zarc pack -L --output ebooks.zarc ~/Documents/Ebooks' ran
    1.06 ± 0.15 times faster than 'tar -caf ebooks.tar.zst ~/Documents/Ebooks'
   11.85 ± 1.54 times faster than 'zip -qr ebooks.zip ~/Documents/Ebooks'
```

#### Archive size

```console
$ dust -sbn0 ebooks.tar.zst
476M ┌── ebooks.tar.zst

$ dust -sbn0 ebooks.zip
477M ┌── ebooks.zip

$ dust -sbn0 ebooks.zarc
478M ┌── ebooks.zarc
```

#### Listing archive contents

```console
$ hyperfine --shell=none --warmup 1 \
  'tar tf ebooks.tar.zst' \
  'unzip -l ebooks.zip' \
  'zarc list-files ebooks.zarc'

Benchmark 1: tar tf ebooks.tar.zst
  Time (mean ± σ):     397.0 ms ±  21.5 ms    [User: 408.4 ms, System: 629.5 ms]
  Range (min … max):   361.1 ms … 429.6 ms    10 runs

Benchmark 2: unzip -l ebooks.zip
  Time (mean ± σ):       2.6 ms ±   0.3 ms    [User: 1.2 ms, System: 1.2 ms]
  Range (min … max):     2.1 ms …   5.1 ms    1018 runs

Benchmark 3: zarc list-files ebooks.zarc
  Time (mean ± σ):       2.3 ms ±   0.5 ms    [User: 1.3 ms, System: 0.8 ms]
  Range (min … max):     1.8 ms …  13.3 ms    1164 runs

Summary
  'zarc list-files ebooks.zarc' ran
    1.13 ± 0.26 times faster than 'unzip -l ebooks.zip'
  173.58 ± 36.29 times faster than 'tar tf ebooks.tar.zst'
```

## TODO

- [x] `zarc pack`
  - [ ] `--append`
  - [ ] `-U` and `-u` flags to set user metadata
  - [x] `--follow-symlinks`
  - [ ] `--follow[-and-store]-external-symlinks`
  - [x] `--level` to set compression level
  - [x] `--zstd` to set Zstd parameters
  - [x] Pack linux attributes
  - [x] Pack linux xattrs
  - [ ] Pack linux ACLS
  - [ ] Pack SELinux attributes
  - [x] Pack mac attributes
  - [x] Pack mac xattrs
  - [x] Pack windows attributes
  - [ ] Pack windows alternate data stream extended attributes
  - [ ] Override user/group
  - [ ] User/group mappings
- [ ] `zarc debug`
- [x] `zarc unpack`
  - [ ] Unpack symlinks
  - [ ] Unpack linux attributes
  - [ ] Unpack linux xattrs
  - [ ] Unpack linux ACLS
  - [ ] Unpack SELinux attributes
  - [ ] Unpack mac attributes
  - [ ] Unpack mac xattrs
  - [ ] Unpack windows attributes
  - [ ] Unpack windows alternate data stream extended attributes
  - [ ] Override user/group
  - [ ] User/group mappings
- [x] `zarc list-files`
  - [ ] `--stat` — with mode, ownership, size, creation.or(modified) date
  - [ ] `--json` — all the info
- [x] Streaming packing
- [x] Streaming unpacking
- [ ] Profile and optimise
- [ ] Pure rust zstd?
  - [ ] Seekable files by adding a blockmap (map of file offsets to blocks)?
- [ ] Dictionary hash to provide trust that a dictionary on decode is the same as one used on encode
- [ ] Bao hashing for streaming verification?
