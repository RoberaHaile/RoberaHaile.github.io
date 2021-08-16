---
layout: post
title:  "WinMemFopen: opening memory streams as regular files in Windows"
date:   2021-06-12 18:02:41 +0300
tags: [Red teaming, programming, evasion]  
---

## Opening memory streams as regular files on Windows

One of my personal projects at a point was developing fully undetectable (FUD) malware in Windows environments. Now, there are a lot of elements and components we have to work on to make our implants FUD, but they are out of scope of this blog. Here, I'm going to focus on one component of remaining under the radar - reducing (eliminating) touching the disk. 

The more our malware implant touches the victim's disk such as creating files and dropping other executables, the higher chance of it getting detected by EDRs and AVs, since it leaves digital footprints. One way to workaround this to resort to operating in memory. Examples include loading an encrypted configuration file to memory and decypting it, accepting payloads (modules) from our C2 server, and loading them on the fly in memory, and others. One might even think about developing a memory-only filesystem for our malware. 

So my project set out to do just that - a way to use arbitrary memory buffers as regular files, perform file I/O operations on them such as open, close, read, write and seek. To achieve this, we need to open the memory as a file stream, and have APIs which can operate on the opened file stream. This is easy in Linux, as Linux has an API called [fmemopen()](http://man7.org/linux/man-pages/man3/fmemopen.3.html). Another API is [open_memstream()](https://man7.org/linux/man-pages/man3/open_memstream.3.html), which opens a stream for writing to a dynamically allocated memory buffer. 

I researched the equivalent of these two functions in Windows, and I couldn't find any suitable API. So, I thought the next step would be to implement the functions by ourselves. But this would be unnecessarily complicated (although interesting). 

After some more digging in the Microsoft docs, I found this gem, [Performing memory file I/0](https://docs.microsoft.com/en-us/windows/win32/multimedia/performing-memory-file-i-o). This is an excerpt from the page. 

> The multimedia file I/O services let you treat a block of memory as a file. This can be useful if you already have a file image in memory. Memory files let you reduce the number of special-case conditions in your code because, for I/O purposes, you can treat memory files as if they were disk-based files. 

Let's get to the I/O functions and use them. 

To open a memory buffer as a file, we use the API [mmioOpen()](https://docs.microsoft.com/en-us/windows/win32/api/mmiscapi/nf-mmiscapi-mmioopen). It can open standard files, memory buffer, or components of a custom storage system. Let's see the definition for mmioOpen. 

```C
HMMIO mmioOpen(
  LPSTR      pszFileName,
  LPMMIOINFO pmmioinfo,
  DWORD      fdwOpen
);
```

It accepts a pointer to C-style string called *pszFilename*, a pointer to [MMIOINFO](https://docs.microsoft.com/en-us/previous-versions//dd757322(v=vs.85)) structure, and a flag. We will make *psZFilename* NULL (because we don't have a filename). Coming to MMIOINFO structure, we have to set some members of the structure. Here is the definition of the structure. 

```C 
typedef struct {
  DWORD      dwFlags;
  FOURCC     fccIOProc;
  LPMMIOPROC pIOProc;
  UINT       wErrorRet;
  HTASK      hTask;
  LONG       cchBuffer;
  HPSTR      pchBuffer;
  HPSTR      pchNext;
  HPSTR      pchEndRead;
  HPSTR      pchEndWrite;
  LONG       lBufOffset;
  LONG       lDiskOffset;
  DWORD      adwInfo[4];
  DWORD      dwReserved1;
  DWORD      dwReserved2;
  HMMIO      hmmio;
} MMIOINFO;
```

The relevant members are *fccIOProc*, *cchBuffer*, *pchBuffer*, *adwInfo*. *fccIOProc* is a four-character which identifies the file's I/O operation. We set this to **FOURCC_MEM**. 

*pchBuffer* is the memory block to be opened as a file. We have to set this to an already allocated memory block. To request that the file I/O manager allocate the memory block, we can set pchBuffer to NULL. 

*cchBuffer* is the initial size of the memory block (*pchBuffer*). 

*adwInfo* is state information maintained by the I/O procedure. Just set this to NULL. 

We set the rest of the members of the structure to zero. 

Now that we have created our structure and initialized the right members for memory block operations, we can pass it to *mmioOpen()*. The third flag of *mmioOpen()* is *fdwOpen*, which is a flag for open operation. we can set the flag to **MMIO_READWRITE**. 

*mmioOpen()* returns a *HMMIO* file handle. Note that this file handle is not a standard file handle, and we should not use it with other file I/O functions other than multimedia file I/O APIs. The function returns NULL if there is an error, and *wErrorRet* member of MMIO structure passed to it will contain the error code (listed on *mmioOpen()* docs). 

Note: files (memory blocks) opened by this function are not automatically closed when our application exits; therefore, we must call *mmioClose()* to close the file handle. 

The next function we are going to use is [mmioRead()](https://docs.microsoft.com/en-us/windows/win32/api/mmiscapi/nf-mmiscapi-mmioread). Here is how it is defined. 

```C
LONG mmioRead(
  HMMIO hmmio,
  HPSTR pch,
  LONG  cch
);
``` 

It accepts the HMMIO file handle returned from *mmioOpen()*, a pointer to buffer to read into (*pch*), and the number of bytes to read (*cch*). On success, it returns the number of bytes read, zero if we have reached the end of file or no more bytes can be read, and -1 on error. 

The third function is [mmioWrite()](https://docs.microsoft.com/en-us/windows/win32/api/mmiscapi/nf-mmiscapi-mmiowrite). Here is the definition. 

```C
LONG mmioWrite(
  HMMIO            hmmio,
  const char _huge *pch,
  LONG             cch
);
```

It is literally the opposite twin of *mmioRead()*. It returns the number of bytes written, or -1 if there was an error. 

The fourth function is [mmioSeek()](https://docs.microsoft.com/en-us/windows/win32/api/mmiscapi/nf-mmiscapi-mmioseek) which is used to change the file position to a custom offset.  

```C
LONG mmioSeek(
  HMMIO hmmio,
  LONG  lOffset,
  int   iOrigin
);
```

Aside from HMMIO file handle, it takes lOffset (offset to change the file position), and iOrigin, which specifies how the offset specified by *lOffset* is interpreted. **SEEK_CUR** seeks to *lOffset* bytes from the current file position; **SEEK_END** seeks to *lOffset* bytes from the end of the file; **SEEK_SET** seeks to *lOffset* bytes from the beginning of the file. 

NOTE: Seeking to an invalid location in the file, such as past the end of the file, might not cause mmioSeek() to return an error, but it might cause subsequent I/O operations on the file to fail. So, we have to implement our own check so that it doesn't happen. 

And finally, [mmioClose()](https://docs.microsoft.com/en-us/windows/win32/api/mmiscapi/nf-mmiscapi-mmioclose) closes the HMMIO file handle we opened earlier. 

```C
MMRESULT mmioClose(
  HMMIO hmmio,
  UINT  fuClose
);
```

There are other cool functions other than these, such as *mmioInstallIOProc()* and *MMIOProc()*, but I'll leave that as an interesting detour to the curious reader. 

I have written a wrapper library around these functions, along with a silly demonstration example [here](https://github.com/RoberaHaile/WinMemFopen). 
