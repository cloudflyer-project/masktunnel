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
import tempfile
import tarfile
import zipfile
from pathlib import Path
from setuptools import setup, find_packages
from setuptools.command.build_py import build_py as _build_py
from setuptools.command.develop import develop as _develop
from urllib.request import urlretrieve

here = Path(__file__).parent.absolute()

# Global variables
_temp_go_dir = None

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


def download_file(url, destination):
    """Download a file from URL to destination."""
    print(f"Downloading {url} to {destination}")
    urlretrieve(url, destination)


def install_go():
    """Download and install Go if not available."""
    global _temp_go_dir
    
    if check_go_installation():
        return
    
    print("Go not found, downloading and installing to temporary directory...")
    
    # Determine platform and architecture
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    # Map architecture names
    arch_map = {
        'x86_64': 'amd64',
        'amd64': 'amd64',
        'i386': '386',
        'i686': '386',
        'arm64': 'arm64',
        'aarch64': 'arm64',
    }
    
    arch = arch_map.get(machine, 'amd64')
    go_version = "1.21.6"
    
    if system == "windows":
        go_filename = f"go{go_version}.windows-{arch}.zip"
    elif system == "darwin":
        go_filename = f"go{go_version}.darwin-{arch}.tar.gz"
    else:  # linux
        go_filename = f"go{go_version}.linux-{arch}.tar.gz"
    go_url = f"https://dl.google.com/go/{go_filename}"
    
    # Create temporary directory for Go installation
    _temp_go_dir = tempfile.mkdtemp(prefix="go_install_")
    temp_dir_path = Path(_temp_go_dir)
    
    try:
        go_archive = temp_dir_path / go_filename
        download_file(go_url, go_archive)
        
        print(f"Installing Go to temporary directory: {temp_dir_path}")
        
        # Extract Go to temporary directory
        if system == "windows":
            with zipfile.ZipFile(go_archive, 'r') as zip_ref:
                zip_ref.extractall(temp_dir_path)
        else:
            with tarfile.open(go_archive, 'r:gz') as tar_ref:
                try:
                    tar_ref.extractall(temp_dir_path, filter='data')
                except TypeError:
                    tar_ref.extractall(temp_dir_path)
        
        # Go is extracted to temp_dir/go/
        go_root = temp_dir_path / "go"
        go_bin = go_root / "bin"
        
        # Update PATH
        current_path = os.environ.get("PATH", "")
        if str(go_bin) not in current_path:
            os.environ["PATH"] = f"{go_bin}{os.pathsep}{current_path}"
        
        print(f"Updated PATH to include Go: {go_bin}")
        
        # Set GOROOT
        os.environ["GOROOT"] = str(go_root)
        
        # Set GOPATH and GOMODCACHE to temporary locations
        go_workspace = temp_dir_path / "go-workspace"
        os.environ["GOPATH"] = str(go_workspace)
        os.environ["GOMODCACHE"] = str(go_workspace / "pkg" / "mod")
        
        # Create directories if they don't exist
        go_workspace.mkdir(exist_ok=True)
        (go_workspace / "pkg" / "mod").mkdir(parents=True, exist_ok=True)
        
        print(f"Go installed successfully to temporary directory: {go_root}")
        
    except Exception as e:
        # Clean up on error
        if _temp_go_dir and Path(_temp_go_dir).exists():
            shutil.rmtree(_temp_go_dir)
            _temp_go_dir = None
        raise e


def cleanup_temp_go():
    """Clean up temporary Go installation."""
    global _temp_go_dir
    if _temp_go_dir and Path(_temp_go_dir).exists():
        print(f"Cleaning up temporary Go installation: {_temp_go_dir}")
        try:
            import stat
            for root, dirs, files in os.walk(_temp_go_dir):
                for d in dirs:
                    os.chmod(os.path.join(root, d), stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
                for f in files:
                    os.chmod(os.path.join(root, f), stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
            shutil.rmtree(_temp_go_dir)
            _temp_go_dir = None
        except Exception as e:
            print(f"Warning: Failed to clean up temporary Go installation: {e}")
            _temp_go_dir = None


def build_cffi_library():
    """Build the Go C-shared library for CFFI."""
    # Determine output library name
    goos = os.environ.get("GOOS", platform.system().lower())
    if goos == "darwin":
        lib_name = "libmasktunnel_ffi.dylib"
    elif goos == "windows":
        lib_name = "masktunnel_ffi.dll"
    else:
        lib_name = "libmasktunnel_ffi.so"
    
    output_dir = here / "masktunnel_ffi"
    output_lib = output_dir / lib_name
    
    # Check if library already exists (e.g., from pre-built wheel or previous build)
    if output_lib.exists():
        print(f"Using existing C-shared library: {output_lib}")
        return
    
    print(f"C-shared library not found, building: {output_lib}")
    
    if not check_go_installation():
        print("Go not found, attempting to install...")
        try:
            install_go()
        except Exception as e:
            print(f"Failed to install Go: {e}")
            raise RuntimeError(
                "Go is required to build masktunnel from source. "
                "Please install Go 1.21+ from https://golang.org/dl/ or use a pre-built wheel."
            )
    
    project_root = here.parent.parent
    ffi_src_dir = here / "masktunnel_go_ffi"
    
    if not ffi_src_dir.exists():
        raise FileNotFoundError(f"Cannot find FFI source directory: {ffi_src_dir}")
    
    # Build the shared library
    env = os.environ.copy()
    env["CGO_ENABLED"] = "1"
    
    try:
        run_command(
            [
                "go",
                "build",
                "-buildmode=c-shared",
                "-o",
                str(output_lib),
                "./masktunnel_go_ffi",
            ],
            cwd=here,
            env=env,
        )
        
        print(f"Successfully built {output_lib}")
        
        # Remove the generated .h file from masktunnel/ (we don't need it in the package)
        h_file = output_dir / lib_name.replace(".so", ".h").replace(".dylib", ".h").replace(".dll", ".h")
        if h_file.exists():
            h_file.unlink()
    except Exception as e:
        raise RuntimeError(
            f"Failed to build masktunnel shared library: {e}\n"
            "Use a pre-built wheel, or ensure Go 1.21+ is installed."
        )


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
    version="1.1.3",
    description="HTTP MITM proxy with browser fingerprinting (CFFI backend)",
    long_description=(here / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    author="CloudFlyer Project",
    author_email="",
    url="https://github.com/cloudflyer-project/masktunnel",
    packages=find_packages(exclude=["tests", "tests.*"]),
    package_data={
        "masktunnel_ffi": ["*.so", "*.dylib", "*.dll", "*.h"],
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
