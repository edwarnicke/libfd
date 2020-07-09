libfd provides a low level Golang FD object that can:

* Be created from (Dev,Ino) if the file is already open
* Be used to send or recv (Dev,Inode) across net.UnixConn

## Details

Under the covers in Linux (and Posix) everything is an inode.  
The pretty file system and socket api we are accustomed to are, in some sense, syntactical
sugar coating over that.

Every inode is specified by a (Dev,Ino) pair.  On linux these are both uint64.

A file descriptor (fd) is a handle in your process for an inode.

Up at the normal Go library, you have net.Conn and *os.File ... but under the covers: all inodes.

libfd makes all that available and manipulable.
