Import os
Import sys
Import argparse # For command-line arguments

# --- Error Handler for os.walk ---
Def handle_walk_error(error):
    “””
    Error handler for os.walk. Prints the error to stderr and continues.
    Called when os.walk cannot list a directory’s contents.
    “””
    Print(f”Error accessing directory: {error}”, file=sys.stderr)

# --- Main Function to Find Files ---
Def find_exe_files(root_paths):
    “””
    Recursively finds all files with the.exe extension within the specified root paths.

    Args:
        Root_paths (list): A list of directory paths (strings) to start searching from.

    Returns:
        List: A list of full paths (strings) to the found.exe files.
              Returns an empty list if no files are found or on error.
    “””
    Exe_files_found =
    If not isinstance(root_paths, list):
        Print(“Error: root_paths must be a list of strings.”, file=sys.stderr)
        Return

    For start_path in root_paths:
        If not os.path.isdir(start_path):
            Print(f”Warning: ‘{start_path}’ is not a valid directory. Skipping.”, file=sys.stderr)
            Continue

        Print(f”Searching in: {start_path}…”)
        # Use os.walk to traverse directories
        # onerror handles directories os.walk itself cannot access
        For root, dirs, files in os.walk(start_path, topdown=True, onerror=handle_walk_error):
            For filename in files:
                # Use try-except to handle errors accessing individual files within accessible directories
                Try:
                    # Construct the full path
                    Full_path = os.path.join(root, filename)

                    # Extract the extension using os.path.splitext
                    _, file_extension = os.path.splitext(filename)

                    # Case-insensitive check for ‘.exe’ extension
                    If file_extension.lower() == ‘.exe’:
                        # Check if the path actually points to a file (optional, but good practice)
                        If os.path.isfile(full_path):
                             Exe_files_found.append(full_path)

                Except OSError as e:
                    # Handles errors during os.path.join, os.path.splitext, or os.path.isfile
                    Print(f”Error processing file ‘{os.path.join(root, filename)}’: {e}”, file=sys.stderr)
                    # Continue to the next file
                    Continue

    Return exe_files_found

# --- Optional: Function to get roots using psutil ---
Def get_search_roots_psutil():
    “””
    Uses psutil (if available) to get a list of potentially searchable mount points.
    Filters out read-only, CD-ROMs, and common problematic virtual FS on Linux.
    “””
    Try:
        Import psutil
    Except ImportError:
        Print(“Warning: psutil library not found. Cannot auto-detect drives.”, file=sys.stderr)
        Print(“Install with: pip install psutil”, file=sys.stderr)
        Return None # Indicate failure

    Partitions = psutil.disk_partitions(all=False) # all=False attempts to exclude virtual FS
    Roots =
    For p in partitions:
        # Basic filtering: skip read-only, optical drives
        If ‘ro’ in p.opts or ‘cdrom’ in p.opts:
            Continue
        # Add platform-specific filtering if needed
        If sys.platform.startswith(‘linux’):
            # Avoid common virtual/special filesystems
            If p.fstype in [‘proc’, ‘sysfs’, ‘tmpfs’, ‘devtmpfs’, ‘cgroup’, ‘fuse.gvfsd-fuse’, ‘snapfuse’]:
                 Continue
        # Ensure mountpoint exists and is a directory before adding
        If os.path.isdir(p.mountpoint):
            Roots.append(p.mountpoint)
        Else:
            Print(f”Warning: psutil reported mountpoint ‘{p.mountpoint}’ not accessible or not a directory. Skipping.”, file=sys.stderr)

    If not roots:
         Print(“Warning: psutil could not find any suitable partitions to search.”, file=sys.stderr)
         Return None

    Return roots

# --- Script Execution ---
If __name__ == “__main__”:
    Parser = argparse.ArgumentParser(description=”Find all.exe files starting from specified root directories.”)
    Parser.add_argument(‘roots’, nargs=’*’, help=”Optional list of root directories to search. If omitted, attempts to search all detected drives (requires psutil).”)
    Parser.add_argument(‘—use-psutil’, action=’store_true’, help=”Force attempt to use psutil to detect all drives, even if roots are provided.”)

    Args = parser.parse_args()

    Search_directories =

    If args.roots:
        Search_directories = args.roots
        If args.use_psutil:
             Print(“Info: --use-psutil flag ignored because specific root directories were provided.”)
    Elif args.use_psutil or not args.roots:
        Print(“Attempting to detect drives using psutil…”)
        Detected_roots = get_search_roots_psutil()
        If detected_roots:
            Search_directories = detected_roots
        Else:
            Print(“Error: Failed to detect drives using psutil. Please specify root directories manually.”, file=sys.stderr)
            Sys.exit(1) # Exit if auto-detection fails and no manual paths given
    Else:
         # Should not happen with current argparse logic, but as fallback:
         Print(“Error: No search roots specified and psutil not used.”, file=sys.stderr)
         Sys.exit(1)


    If search_directories:
        Print(f”Starting search for.exe files in: {‘, ‘.join(search_directories)}”)
        Found_files = find_exe_files(search_directories)

        If found_files:
            Print(f”\nFound {len(found_files)}.exe files:”)
            For f_path in found_files:
                Print(f_path)
        Else:
            Print(“\nNo.exe files found in the specified locations.”)
    Else:
        Print(“No valid search directories determined. Exiting.”)
