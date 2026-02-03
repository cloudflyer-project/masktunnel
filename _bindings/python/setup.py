#!/usr/bin/env python3
"""
Setup script for masktunnel Python bindings (CFFI backend).

MaskTunnel is an HTTP MITM proxy with browser fingerprinting capabilities.
This package provides Python bindings using CFFI for the Go implementation.
"""

import os
import sys
import shutil
import subprocess
import platform
from pathlib import Path
from setuptools import setup, find_packages
from setuptools.command.build_py import build_py as _build_py
from setuptools.command.develop import develop as _develop

here = Path(__file__).parent.absolute()

# Ensure Go builds do not require VCS (git) metadata
current_goflags = os.environ.get("GOFLAGS", "").strip()
if "-buildvcs=false" not in current_goflags:
    os.environ["GOFLAGS"] = (current_goflags + (" " if current_goflags else "") + "-buildvcs=false").strip()

install_requires = [
    "setuptools>=40.0",
    "click>=8.0",
    "loguru",
    "rich",
    "cffi>=1.15",
]

extras_require = {
    "dev": [
        "pytest>=6.0",
        "pytest-cov>=2.10",
        "pytest-mock>=3.0",
        "pytest-xdist",
        "black>=21.0",
        "flake8>=3.8",
        "mypy>=0.800",
        "httpx[http2]",
        "requests",
        "pysocks",
    ],
}


def run_command(cmd, cwd=None, env=None):
    """Run a command and return the result."""
    print(f"Running: {' '.join(cmd)}")
    try:
        if env is None:
            env = os.environ.copy()
        result = subprocess.run(
            cmd,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e}")
        print(f"stdout: {e.stdout}")
        print(f"stderr: {e.stderr}")
        raise


def check_go_installation():
    """Check if Go is installed."""
    try:
        result = run_command(["go", "version"])
        print(f"Found Go: {result}")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Go is not installed or not in PATH")
        return False


def build_cffi_library():
    """Build the Go C-shared library for CFFI."""
    if not check_go_installation():
        raise RuntimeError("Go is required to build masktunnel. Please install Go 1.21 or later.")
    
    project_root = here.parent.parent
    ffi_src_dir = here / "masktunnel_go_ffi"
    
    if not ffi_src_dir.exists():
        raise FileNotFoundError(f"Cannot find FFI source directory: {ffi_src_dir}")
    
    # Determine output library name
    goos = os.environ.get("GOOS", platform.system().lower())
    if goos == "darwin":
        lib_name = "libmasktunnel.dylib"
    elif goos == "windows":
        lib_name = "masktunnel.dll"
    else:
        lib_name = "libmasktunnel.so"
    
    output_dir = here / "masktunnel"
    output_lib = output_dir / lib_name
    
    print(f"Building C-shared library: {output_lib}")
    
    # Build the shared library
    env = os.environ.copy()
    env["CGO_ENABLED"] = "1"
    
    run_command(
        ["go", "build", "-buildmode=c-shared", "-o", str(output_lib), "."],
        cwd=ffi_src_dir,
        env=env
    )
    
    print(f"Successfully built {output_lib}")
    
    # Remove the generated .h file from masktunnel/ (we don't need it in the package)
    h_file = output_dir / lib_name.replace(".so", ".h").replace(".dylib", ".h").replace(".dll", ".h")
    if h_file.exists():
        h_file.unlink()


class BuildPyWithCFFI(_build_py):
    """Custom build_py that builds the CFFI library first."""
    
    def run(self):
        build_cffi_library()
        super().run()


class DevelopWithCFFI(_develop):
    """Custom develop that builds the CFFI library first."""
    
    def run(self):
        build_cffi_library()
        super().run()


setup(
    name="masktunnel",
    version="1.1.0",
    description="HTTP MITM proxy with browser fingerprinting (CFFI backend)",
    long_description=(here / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    author="CloudFlyer Project",
    author_email="",
    url="https://github.com/cloudflyer-project/masktunnel",
    packages=find_packages(exclude=["tests", "tests.*"]),
    package_data={
        "masktunnel": ["*.so", "*.dylib", "*.dll", "*.h"],
        "masktunnel_ffi": [],
    },
    python_requires=">=3.9",
    install_requires=install_requires,
    extras_require=extras_require,
    cmdclass={
        "build_py": BuildPyWithCFFI,
        "develop": DevelopWithCFFI,
    },
    entry_points={
        "console_scripts": [
            "masktunnel=masktunnel._cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Go",
    ],
    zip_safe=False,
)
