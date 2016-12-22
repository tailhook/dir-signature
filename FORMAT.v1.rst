==================================
Directory Signature File Format v1
==================================

The format is a text file with ascii-only characters.


Header
======

File starts with a header line, which looks like::

    DIRSIGNATURE.v1 sha512/256 block_size=32768

It consists of three parts separated by a single space, all of them are
case sensitive and order is fixed. Parts have the following meaning:

1. ``DIRSIGNATURE.v1 `` is a signature of a file format and version.
   Only ``v1` format is defined by this specification.

2. Is a hash type (must be all lower case). This specification defines two
   hash types ``blake2b/256`` (which is blake2b with 256 bit hash) and
   ``sha512/256`` which means ``sha512`` truncated to a 256 bits.
   Other hash kinds might be added in future. It's expected that sha512/256
   will be supported by every implementation and others are optional.

3. Space separated key value pairs. This specification defines only
   ``block_size``. It must be the first key in the header. This specification
   requires to support only ``32768`` block size. Other block sizes can be
   added in future. Additional key value pairs may exists and may be skipped
   by the parser (but must be accounted in final hash, see below).


File List
=========

Directories and files follow header and go in the following format. Example::

    /
      file1.txt f 0
    /dir
      file2.txt f 1 a4abd4448c49562d828115d13a1fccea927f52b4d5459297f8b43e42da89238b
      symlink s ../file1.txt
    /dir/subdir

The rules are:

* Directory lines start with slash ``/``, directory path is specified relative
  to the root of the scanned directory
* Files and symlinks start with exactly two space ``  `` and followed by a name
  relative to the directory, followed by attributes (see below)
* No other kinds of entries are allowed
* Directory does not have any attributes and should be recreated with
  appropriate umask or use mode ``755`` when created
* All fields in file entries are space-separated
* In file (and directory) names all control characters, non-ascii,
  non-printable characters and space are escaped using hex escapes (e.g. space
  is ``\x20``), unicode characters are first serialized to utf-8 then escaped
  (specifically all chars with code <= 0x20 and >= 0x7F are escaped)
* Line-endings are always ``\n``
* Directory paths are sorted as utf-8-encoded binary strings
* File names are sorted locally inside the directory as utf-8-encoded binary
  strings


File Entries
============

Files can be of the following types:

* ``f`` -- regular file (recommended mode ``644``)
* ``x`` -- executable (recommended mode ``755``)
* ``s`` -- a symlink

A symlink is a stored in the index as name followed by ``s`` followed by a
symlink's destination (obtained by ``readlink()``).

Files (both executables and not) are indexed as name followed by ``f`` or
``x``, followed by file size, followed by a lowercase hex-encoded hashes for
each block.  If last block of file is less than ``block_size`` it's not padded
only bytes that exist in file are hashed.

Files with the size of zero do not have any hashes (finish line by zero file
length). In general number of hashes may be calculates as
``ceil(file_size / block_size)``.


Footer
======

Footer consists of a hash of the all lines above, including header line as
written in the file hashed with the same hash function (and serialized as a
lowercase hex value). Footer ends with a newline. And this is the final line
of the file.

If you're writing a parser any line except the first that does not start with
a slash ``/`` or a space `` `` must be considerered a footer.


Full Example
============

Here is an example of the simple directory::

    DIRSIGNATURE.v1 sha512/256 block_size=32768
    /
      file2.txt f 18 c4cadd1e2e2aded1cdb2ba48fdfe8a831d9236042aec16472725d45b001c1ad5
    /sub2
      hello.txt f 6 e0494295cc1dfdd443d09f81913881a112745174778cc0c224ccc7137024fe41
    /subdir
      bigdata.bin f 81920 768007e06b0cd9e62d50f458b9435c6dda0a6d272f0b15550f97c478394b7433 768007e06b0cd9e62d50f458b9435c6dda0a6d272f0b15550f97c478394b7433 6eb7f16cf7afcabe9bdea88bdab0469a7937eb715ada9dfd8f428d9d38d86133
      file3.txt f 12 b130fa20a2ba5a3d9976e6c15e8a59ad9e5cbbc52536a4458952872cda5c218d
    c23f2579827456818fc855c458d1ad7339d144b57ee247a6628e4fc8e39958bb

