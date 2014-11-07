process_memory_blob
===================

Tools to process memory blobs extracted from embedded device memory components.

# process_mem_blob.py: 
Processes a file and locates sections that contain data. This is to help analysts pinpoint sections of a memory blob rather than just scrolling through the whole thing looking for values that are not 0x00 or 0xff.

```
user> python process_memory_blob.py -h
process_memory_blob.py [-h] [-d] [-n int] [-l int] [-s int] [-m] [-M list] [-e] [-z] [-f <binary file>]
    -h: This is it.
    -d: Turn on debugging.  Default: off
    -n <int>: number of concequtive 0xff to test for no data at this location.
    -l <int>: number of bytes to print when data is located.
    -s <int>: number of bytes to skip forward during testing.
    -f <binary file>: binary file that contains the data.
    -e: Perform entropy testing.  No data is printed, just highlighted entropy scores.
    -b: Perform base64 printing.
    -m: Perform magic-based searching and printing.
    -M: Perform magic-based searching and printing. List must be comma separated with no spaces nor non-ASCII characters nor comma.
    -z: Default testing is for 0xff.  This will add 0x00 to the testing.

All data is printed to standard out.

You should consider the size of the blob as well.  This script process different points
of the file and then goes back and prints from the locations.  So, the object created
will not be too large.  But, if there are a LOT of locations to print the list will
get large.  Python has two issues: large objects and slow printing.  Therefore, a large
file might slow your system down due to memory usage (for the large object) and CPU
usage for printing to the screen.  You can fix this by rewriting this in C or by
using a better memory processor.

```

# process_mem_blob_chunks.py: 
Processes a file and extracts "extra" data when dumping tools pull (for example) 264 bytes rather than 256 bytes per block. This extra data may be used by the memory component for error correction or other functionality. But, if it is present in the memory blob then it needs to be removed.

# process_mem_blog_keys.py
Processes a file looking for keys of a specific length. This is done by testing for entropy specific to the key size. The user has the option to purge consecutive positive hits that could indicate larger keys or just sections of data with entropy matching that key size (such as firmware).

```
user> python process_mem_blob_keys.py -h
process_mem_blob_keys.py [-h] [-d] [-k int] [-f <binary file>]
    -h: This is it.
    -d: Turn on debugging.  Default: off
    -p: Turn on purging to filter consecutive items. This could generate false negatives.  Default: off
    -s: Turn off progress bar. This is useful when redirecting to a file.  Default: on
    -k <int>: number of bytes in key
    -f <binary file>: binary file that contains the data.

All data is printed to standard out.

```

# progressBar.py
Displays how much of the file has been processed as it is being processed. Borrowed from cyphunk:

- http://deadhacker.com/2007/05/13/finding-entropy-in-binary-files/
- https://github.com/cyphunk/sectk/tree/master/often/entropy_analysis


InGuardians, Inc.<br>
http://www.inguardians.com<br>
http://labs.inguardians.com<br>
