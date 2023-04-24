"""Compiles requirements.in files to a requirements.txt."""

import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Iterable, Optional, Sequence

from piptools.locations import CACHE_DIR
from piptools.scripts.compile import cli as pip_compile_cli


def pipcompile(
    *,
    input_files: Iterable[Path],
    output_file: Optional[Path] = None,
    optional_args: Optional[Sequence[str]] = None,
) -> int:
    """Compiles a requirements.txt file from requirements.in files.

    Args:
        input_files: An iterable of paths to requirements.in files.
        output_file: Path to the requirements.txt file to produce.
        optional_args: Pptional list of pipcompile flags to replace internal defaults, excluding the output and input
            file arguments and the possible use of --cache-dir.

    Returns:
        exit status of the pip compilation.
    """
    args = []

    # Try to use the default cache dir if possible, but if it is not writable (e.g. during remote execution), use a dir
    # in the current working directory instead, which will be writable.
    try:
        Path(CACHE_DIR).mkdir(parents=True, exist_ok=True)
    except OSError:  # OSError: [Errno 30] Read-only file system: '/home/user/.cache/'
        pass
    if not os.access(CACHE_DIR, os.W_OK):
        cache_dir = os.fspath(Path.cwd() / ".cache/pip-tools")
        args.extend(["--cache-dir", cache_dir])

    if optional_args is None:
        optional_args = [
            "--generate-hashes",
            "--allow-unsafe",
            "--no-emit-index-url",
            "--quiet",
        ]
    args.extend(optional_args)

    if output_file:
        args.extend(["--output-file", os.fspath(output_file)])

    for input_file in input_files:
        args.append(os.fspath(input_file))

    return pip_compile_cli.main(args=args, standalone_mode=False) or 0
