# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.0](https://github.com/passcod/zarc/releases/tag/zarc-v0.0.0) - 2024-01-20

### Other
- 0.0.0
- More windows fix
- unpack --verify
- Print digest when packing
- Okay, and?
- More fixes
- Sure whatever
- Fix ci
- Reorg spec a bit
- Allow trailer to be read both ways
- Tolerate unknown directory element types
- Remove signing
- Cache uid/gid lookups
- Ignore not being able to read (x)attrs
- Unpack base metadata
- User/group names are always ascii, so skip the bytestring encoding
- Remove legacy directory
- Clippy
- File builder
- Split up encode
- Decode new directory format
- Split metadata helpers
- Rename frame_hash to digest
- Write new directory
- Check the check byte before modifying the offset
- Add a check byte to the trailer
- Reorganise decoder and read/write new trailer
- Split up format
- Get this building again
- Whoops save previous refactor
- Change encoding to ideal api
- New directory header format
- Unprefixed common attrs and read-only as attr
- Split up decoder
- Open multiple read-only cursors into the file
- Fix lifetime issues
- Attempt to unpack
- Filter files
- Distinguish hardlinks and symlinks
- Read directory
- Add CborString::to_path
- Read directory header
- Decode headers and trailers
- Start writing decode
- Assert zarc magic in header
- Allow headers to be parsed independently
- Split ozarc out
