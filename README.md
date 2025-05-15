# Python for Cybersecurity Analysts

## Locate Executable Files with Python

This project entails the construction of a Python script to effectively locate .exe files across a computer's filesystem. The solution leverages the standard os and os.path modules, employing os.walk for efficient recursive directory traversal and os.path.splitext for accurate file extension identification. Key considerations for robustness include platform-independent path construction using os.path.join and comprehensive error handling using both try...except blocks within the processing loop and the onerror callback for os.walk to manage permissions issues gracefully.

The definition of the search scope (the root directories) is critical. While specific paths can be provided manually, the third-party psutil library offers a cross-platform method for programmatically discovering potential starting points (drives/mount points), although careful filtering is often required for practical application. The final script presented integrates these components, providing a functional and adaptable tool for filesystem searching. The alternatives using pathlib or glob offer different syntaxes but generally less control over the traversal and error handling compared to the os.walk-based approach detailed herein.
