#!/usr/bin/env python3
"""Setup script for masktunnel Python bindings.

This package builds native bindings from the Go implementation using gopy.
"""

import os
import sys
import shutil
import subprocess
import platform
import tempfile
import importlib.machinery
import tarfile
import zipfile
from pathlib import Path
from setuptools import setup, find_packages
import setuptools
from urllib.request import urlretrieve
from setuptools.command.sdist import sdist as _sdist
from setuptools.command.build_py import build_py as _build_py
from setuptools.command.develop import develop as _develop
from setuptools.command.install import install as _install
from typing import Optional

here = Path(__file__).parent.absolute()

_temp_go_dir: Optional[str] = None
_temp_py_venv_dir: Optional[Path] = None

current_goflags = os.environ.get("GOFLAGS", "").strip()
if "-buildvcs=false" not in current_goflags:
    os.environ["GOFLAGS"] = (current_goflags + (" " if current_goflags else "") + "-buildvcs=false").strip()

install_requires = [
    "setuptools>=40.0",
]

extras_require = {
    "dev": [
        "pytest>=6.0",
        "pytest-xdist",
        "build",
        "wheel",
    ],
}


def ensure_placeholder_masktunnellib() -> None:
    pkg_dir = here / "masktunnellib"
    init_py = pkg_dir / "__init__.py"
    try:
        pkg_dir.mkdir(parents=True, exist_ok=True)
        if not init_py.exists():
            init_py.write_text("# Placeholder; real contents generated during build\n")
    except Exception as e:
        print(f"Warning: failed to create placeholder masktunnellib: {e}")


def _expected_binary_names() -> list[str]:
    candidates: list[str] = []
    for suffix in importlib.machinery.EXTENSION_SUFFIXES:
        candidates.append(f"_masktunnellib{suffix}")
    pyver = f"{sys.version_info.major}{sys.version_info.minor}"
    candidates.append(f"_masktunnellib.cpython-{pyver}.so")
    candidates.append(f"_masktunnellib.cp{pyver}.pyd")
    return candidates


def is_masktunnellib_built(lib_dir: Path) -> bool:
    if not lib_dir.exists():
        return False
    for name in _expected_binary_names():
        if (lib_dir / name).exists():
            return True
    return False


def prune_foreign_binaries(lib_dir: Path) -> None:
    if not lib_dir.exists():
        return
    keep_names = set(_expected_binary_names())
    for p in lib_dir.iterdir():
        if not p.is_file():
            continue
        if p.name.startswith("_masktunnellib") and p.suffix in {".so", ".pyd", ".dll", ".dylib"}:
            if p.name not in keep_names:
                try:
                    p.unlink()
                    print(f"Pruned foreign binary: {p}")
                except Exception as e:
                    print(f"Warning: failed to remove {p}: {e}")


def run_command(cmd, cwd=None, env=None):
    print(f"Running: {' '.join(str(x) for x in cmd)}")
    if env is None:
        env = os.environ.copy()
    result = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Command failed: {result.returncode}")
        print(f"stdout: {result.stdout}")
        print(f"stderr: {result.stderr}")
        raise subprocess.CalledProcessError(result.returncode, cmd, output=result.stdout, stderr=result.stderr)
    return result.stdout.strip()


def _venv_scripts_dir(venv_dir: Path) -> Path:
    system = platform.system().lower()
    if system == "windows":
        return venv_dir / "Scripts"
    return venv_dir / "bin"


def create_temp_virtualenv() -> tuple[Path, Path]:
    """Create a temporary Python virtual environment and return (venv_dir, python_exe)."""
    global _temp_py_venv_dir
    _temp_py_venv_dir = Path(tempfile.mkdtemp(prefix="masktunnel_pyvenv_"))
    venv_dir = _temp_py_venv_dir / "venv"
    run_command([sys.executable, "-m", "venv", str(venv_dir)])
    scripts_dir = _venv_scripts_dir(venv_dir)
    python_exe = scripts_dir / ("python.exe" if platform.system().lower() == "windows" else "python")
    return venv_dir, python_exe


def ensure_pip_for_python(python_executable: Path) -> list[str]:
    """Ensure pip is available for the given interpreter and return invocation list."""
    try:
        run_command([str(python_executable), "-m", "pip", "--version"])
        return [str(python_executable), "-m", "pip"]
    except Exception:
        pass

    try:
        run_command([str(python_executable), "-m", "ensurepip", "--upgrade"])
        run_command([str(python_executable), "-m", "pip", "--version"])
        return [str(python_executable), "-m", "pip"]
    except Exception:
        pass

    raise RuntimeError("pip is required to build masktunnel bindings")


def desired_gotoolchain() -> str:
    """Return a GOTOOLCHAIN value.

    The goal is to avoid breakages when the system Go version is newer than
    some transitive dependencies used by gopy.
    """
    override = os.environ.get("MASKTUNNEL_GOTOOLCHAIN", "").strip()
    if override:
        return override

    # Prefer toolchain from project go.mod if present.
    for mod_path in (here / "go.mod", here.parent.parent / "go.mod"):
        try:
            if mod_path.exists():
                text = mod_path.read_text(encoding="utf-8")
                for line in text.splitlines():
                    line = line.strip()
                    if line.startswith("toolchain "):
                        return line.split(" ", 1)[1].strip()
        except Exception:
            pass
    return ""


def _ensure_go_bins_on_path(env: dict) -> None:
    """Ensure GOBIN/GOPATH/bin are on PATH so newly installed tools are discoverable."""
    try:
        gobin = run_command(["go", "env", "GOBIN"], env=env) or ""
    except Exception:
        gobin = ""
    try:
        gopath = run_command(["go", "env", "GOPATH"], env=env) or ""
    except Exception:
        gopath = ""

    candidate_dirs: list[Path] = []
    if gobin.strip():
        candidate_dirs.append(Path(gobin.strip()))
    if gopath.strip():
        candidate_dirs.append(Path(gopath.strip()) / "bin")

    current_path = env.get("PATH", "")
    parts = [p for p in current_path.split(os.pathsep) if p]
    for d in candidate_dirs:
        d_str = str(d)
        if d_str and d_str not in parts:
            parts.insert(0, d_str)
    env["PATH"] = os.pathsep.join(parts)


def check_go_installation() -> bool:
    try:
        out = run_command(["go", "version"])
        print(f"Found Go: {out}")
        return True
    except Exception:
        return False


def download_file(url: str, destination: Path) -> None:
    """Download a file from URL to destination."""
    print(f"Downloading {url} to {destination}")
    urlretrieve(url, destination)


def install_go() -> None:
    """Download and install Go if not available."""
    global _temp_go_dir

    if check_go_installation():
        return

    print("Go not found, downloading and installing to temporary directory...")

    system = platform.system().lower()
    machine = platform.machine().lower()

    arch_map = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "i386": "386",
        "i686": "386",
        "arm64": "arm64",
        "aarch64": "arm64",
    }

    arch = arch_map.get(machine, "amd64")
    go_version = "1.21.6"

    if system == "windows":
        go_filename = f"go{go_version}.windows-{arch}.zip"
    elif system == "darwin":
        go_filename = f"go{go_version}.darwin-{arch}.tar.gz"
    else:
        go_filename = f"go{go_version}.linux-{arch}.tar.gz"
    go_url = f"https://dl.google.com/go/{go_filename}"

    _temp_go_dir = tempfile.mkdtemp(prefix="go_install_")
    temp_dir_path = Path(_temp_go_dir)

    try:
        go_archive = temp_dir_path / go_filename
        download_file(go_url, go_archive)

        print(f"Installing Go to temporary directory: {temp_dir_path}")

        if system == "windows":
            with zipfile.ZipFile(go_archive, "r") as zip_ref:
                zip_ref.extractall(temp_dir_path)
        else:
            with tarfile.open(go_archive, "r:gz") as tar_ref:
                try:
                    tar_ref.extractall(temp_dir_path, filter="data")
                except TypeError:
                    tar_ref.extractall(temp_dir_path)

        go_root = temp_dir_path / "go"
        go_bin = go_root / "bin"

        current_path = os.environ.get("PATH", "")
        if str(go_bin) not in current_path:
            os.environ["PATH"] = f"{go_bin}{os.pathsep}{current_path}"

        print(f"Updated PATH to include Go: {go_bin}")

        os.environ["GOROOT"] = str(go_root)

        go_workspace = temp_dir_path / "go-workspace"
        os.environ["GOPATH"] = str(go_workspace)
        os.environ["GOMODCACHE"] = str(go_workspace / "pkg" / "mod")

        go_workspace.mkdir(exist_ok=True)
        (go_workspace / "pkg" / "mod").mkdir(parents=True, exist_ok=True)

        print(f"Go installed successfully to temporary directory: {go_root}")

    except Exception as e:
        if _temp_go_dir and Path(_temp_go_dir).exists():
            shutil.rmtree(_temp_go_dir)
            _temp_go_dir = None
        raise e


def cleanup_temp_go() -> None:
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


def prepare_go_sources() -> Path:
    go_src_dir = here / "masktunnel_go"

    if go_src_dir.exists() and (go_src_dir / "python.go").exists():
        print(f"Using existing Go sources in {go_src_dir}")
        return go_src_dir

    print("Preparing Go source files...")

    project_root = here.parent.parent
    if not (project_root / "go.mod").exists():
        raise FileNotFoundError("Cannot find project root with go.mod file")

    if go_src_dir.exists():
        shutil.rmtree(go_src_dir)
    go_src_dir.mkdir()

    for file in ["go.mod", "go.sum"]:
        src = project_root / file
        if src.exists():
            shutil.copy2(src, here / file)

    for go_file in project_root.glob("*.go"):
        shutil.copy2(go_file, go_src_dir / go_file.name)

    print(f"Go sources prepared in {go_src_dir}")
    return go_src_dir


def install_gopy_and_tools() -> None:
    # Try to install Go if not available
    install_go()

    if not check_go_installation():
        raise RuntimeError("Go is required to build masktunnel bindings")

    env = os.environ.copy()
    tc = desired_gotoolchain()
    if tc:
        env["GOTOOLCHAIN"] = tc

    run_command(["go", "install", "github.com/go-python/gopy@latest"], env=env)
    run_command(["go", "install", "golang.org/x/tools/cmd/goimports@latest"], env=env)
    _ensure_go_bins_on_path(env)
    os.environ["PATH"] = env.get("PATH", os.environ.get("PATH", ""))


def build_python_bindings(vm_python: Optional[str] = None) -> None:
    print("Building Python bindings with gopy...")

    go_src_dir = prepare_go_sources()
    temp_files: list[Path] = []

    try:
        lib_dir = here / "masktunnellib"
        if lib_dir.exists():
            shutil.rmtree(lib_dir)

        env = os.environ.copy()
        env["CGO_ENABLED"] = "1"
        env["CGO_LDFLAGS_ALLOW"] = ".*"

        tc = desired_gotoolchain()
        if tc:
            env["GOTOOLCHAIN"] = tc

        target_vm = vm_python or sys.executable

        gopy_executable = shutil.which("gopy", path=env.get("PATH", ""))
        if not gopy_executable:
            raise FileNotFoundError("gopy executable not found on PATH")

        cmd = [
            gopy_executable,
            "build",
            f"-vm={target_vm}",
            f"-output={lib_dir}",
            "-name=masktunnellib",
            "-no-make=true",
        ]

        if platform.system().lower() == "linux":
            cmd.append("-dynamic-link=true")

        cmd.append("./masktunnel_go")

        run_command(cmd, cwd=here, env=env)

        # Fix potential C23 bool conflicts in generated C code.
        lib_go = lib_dir / "masktunnellib.go"
        if lib_go.exists():
            content = lib_go.read_text(encoding="utf-8")
            if "typedef uint8_t bool;" in content:
                content = content.replace(
                    "typedef uint8_t bool;",
                    "#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L\ntypedef uint8_t bool;\n#endif",
                )
                lib_go.write_text(content, encoding="utf-8")

        run_command(["go", "mod", "tidy"], cwd=here)

        prune_foreign_binaries(lib_dir)

    finally:
        for p in temp_files:
            try:
                if p.exists():
                    p.unlink()
            except Exception:
                pass

        try:
            if go_src_dir.exists():
                shutil.rmtree(go_src_dir)
        except Exception:
            pass

        for file in ["go.mod", "go.sum"]:
            f = here / file
            if f.exists():
                try:
                    f.unlink()
                except Exception:
                    pass


def ensure_python_bindings() -> None:
    lib_dir = here / "masktunnellib"

    if not is_masktunnellib_built(lib_dir):
        print("masktunnellib not built or only placeholder found, building...")

        try:
            # Try to install Go if not available
            install_go()

            if not check_go_installation():
                raise RuntimeError(
                    "Go is required to build masktunnel from source. Please install Go 1.22+ or use a pre-built wheel."
                )

            install_gopy_and_tools()

            venv_dir, venv_python = create_temp_virtualenv()
            pip_cmd = ensure_pip_for_python(venv_python)
            run_command(pip_cmd + ["install", "--upgrade", "pip"])
            run_command(pip_cmd + ["install", "pybindgen", "wheel", "setuptools"])

            build_python_bindings(vm_python=str(venv_python))

        except Exception as e:
            print(f"Failed to build Python bindings: {e}")
            raise RuntimeError(
                f"Failed to build masktunnel from source: {e}\n"
                "This may be due to missing dependencies or incompatible system.\n"
                "Try installing a pre-built wheel or ensure Go 1.21+ is installed."
            )
        finally:
            # Clean up temporary Go installation
            cleanup_temp_go()
            # Clean up temporary Python virtual environment
            try:
                if _temp_py_venv_dir and _temp_py_venv_dir.exists():
                    shutil.rmtree(_temp_py_venv_dir)
            except Exception:
                pass

        if not is_masktunnellib_built(lib_dir):
            raise RuntimeError("Failed to build Python bindings (artifacts missing)")
    else:
        prune_foreign_binaries(lib_dir)


class SdistWithGoSources(_sdist):
    def run(self):
        go_src_dir = None
        created_files = []
        try:
            go_src_dir = prepare_go_sources()
            for fname in ["go.mod", "go.sum"]:
                fpath = here / fname
                if fpath.exists():
                    created_files.append(fpath)
            super().run()
        finally:
            try:
                if go_src_dir and Path(go_src_dir).exists():
                    shutil.rmtree(go_src_dir)
            except Exception:
                pass
            for fpath in created_files:
                try:
                    if fpath.exists():
                        fpath.unlink()
                except Exception:
                    pass


class BuildPyEnsureBindings(_build_py):
    def run(self):
        ensure_placeholder_masktunnellib()
        ensure_python_bindings()
        prune_foreign_binaries(here / "masktunnellib")
        super().run()


class DevelopEnsureBindings(_develop):
    def run(self):
        ensure_placeholder_masktunnellib()
        ensure_python_bindings()
        super().run()


class InstallEnsureBindings(_install):
    def run(self):
        ensure_placeholder_masktunnellib()
        ensure_python_bindings()
        super().run()


class BinaryDistribution(setuptools.Distribution):
    def has_ext_modules(_):
        return True


def get_long_description() -> str:
    local_readme = here / "README.md"
    if local_readme.exists():
        return local_readme.read_text(encoding="utf-8")
    return "Python bindings for MaskTunnel - an HTTP MITM proxy with browser fingerprinting."


ensure_placeholder_masktunnellib()

setup(
    name="masktunnel",
    version="0.1.0",
    description="Python bindings for MaskTunnel (Go)",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    author="cloudflyer-project",
    url="https://github.com/cloudflyer-project/masktunnel",
    license="GPL-3.0",
    packages=find_packages(include=["masktunnellib", "masktunnellib.*", "masktunnel"]),
    package_data={
        "masktunnellib": ["*.py", "*.so", "*.pyd", "*.dll", "*.dylib", "*.h", "*.c", "*.go"],
    },
    include_package_data=True,
    install_requires=install_requires,
    extras_require=extras_require,
    python_requires=">=3.9",
    zip_safe=False,
    platforms=["any"],
    distclass=BinaryDistribution,
    cmdclass={
        "sdist": SdistWithGoSources,
        "build_py": BuildPyEnsureBindings,
        "develop": DevelopEnsureBindings,
        "install": InstallEnsureBindings,
    },
)
