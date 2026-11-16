"""Build-time copying of the single reviewed catalog source tree."""

import json
from pathlib import Path
import shutil

from setuptools import setup
from setuptools.command.build_py import build_py


def catalog_sources():
    root = Path(__file__).resolve().parent / "catalog"
    manifest = root / "catalog.json"
    data = json.loads(manifest.read_text(encoding="utf-8"))
    yield manifest, Path("catalog.json")
    for name, tool in data["tools"].items():
        if tool["definition"] != name + ".toml" or tool["role"] != "roles/" + name:
            raise ValueError("invalid catalog source path")
        yield root / tool["definition"], Path(tool["definition"])
        role = root / tool["role"]
        for source in sorted(role.rglob("*")):
            if source.is_symlink():
                raise ValueError("symlink in catalog source")
            if source.is_file():
                relative = source.relative_to(role)
                if "__pycache__" in relative.parts or source.suffix in {".pyc", ".pyo"}:
                    continue
                if relative.parts[0] not in {"tasks", "meta", "files", "defaults", "vars", "handlers"} or source.suffix not in {".yml", ".yaml", ".py", ".json", ".toml"}:
                    raise ValueError("unexpected catalog source asset")
                yield source, source.relative_to(root)


class BuildPy(build_py):
    def run(self):
        super().run()
        destination = Path(self.build_lib) / "estus" / "_catalog"
        if destination.exists():
            shutil.rmtree(destination)
        for source, relative in catalog_sources():
            if source.is_symlink() or not source.is_file():
                raise ValueError("catalog source must be a regular file")
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)

    def get_outputs(self, include_bytecode=True):
        return super().get_outputs(include_bytecode) + [
            str(Path(self.build_lib) / "estus" / "_catalog" / relative)
            for _, relative in catalog_sources()
        ]

    def get_source_files(self):
        root = Path(__file__).resolve().parent
        return super().get_source_files() + [str(source.relative_to(root)) for source, _ in catalog_sources()]


# Register before setuptools-rust finalizes the Distribution. A TOML cmdclass
# table replaces the plugin's complete command map, including build_ext.
setup(cmdclass={"build_py": BuildPy})
