# Tester scripting

The `test_fs.c` program accepts a `script` command which reads a sequence of
commands from a specified file, and performs them on a filesystem.

This scripting ability is particularly useful to test your reading and writing
functions (Phase 4), and check that your implementation properly handles the
special cases (e.g., R/W operations from a non-null offset, small R/W operations
within a block, large R/W operations spanning multiple blocks, etc.).

## Usage

The first argument to the script command is the name of the virtual block device
file and the second is the name of the script file.

The script file contains commands of the following form (tab-delimited, one per
line):

`MOUNT`
: Mounts the file system given on the test script command line.

`UMOUNT`
: Unmounts currently mounted file system if mounted.

`CREATE	<filename>`
: Create empty file named `<filename>` on filesystem.

`DELETE	<filename>`
: Delete file named `<filename>` from filesystem.

`OPEN	<filename>`
: Open file named `<filename>` on filesystem.

`CLOSE`
: Close currently opened file.

`SEEK	<offset>`
: Seeks to the given offset.

`WRITE	DATA	<data>`
: Writes `<data>` at the current offset given in the script file.

`WRITE	FILE	<filename>`
: Writes data read from file located on host computer with name `<filename>`.

`READ	<len>	DATA	<data>`
: Reads `<len>` bytes from the current offset, and compares it to `<data>`.

`READ	<len>	FILE	<filename>`
: Reads `<len>` bytes from the current offset, and compares it to the file
located on host computer with name `<filename>`.



