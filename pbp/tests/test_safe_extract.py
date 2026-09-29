#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import io
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("safe_extract", ROOT / "safe-extract.py")
assert SPEC and SPEC.loader
safe_extract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(safe_extract)


class SafeExtractTests(unittest.TestCase):
    def test_extracts_regular_zip_and_preserves_executable_class(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive_path = root / "good.zip"
            target = root / "target"
            target.mkdir()
            with zipfile.ZipFile(archive_path, "w") as archive:
                info = zipfile.ZipInfo("browser/camoufox-bin")
                info.external_attr = (stat.S_IFREG | 0o755) << 16
                archive.writestr(info, b"binary")
            previous_umask = os.umask(0o077)
            try:
                safe_extract.extract_zip(archive_path, target, 1024)
            finally:
                os.umask(previous_umask)
            output = target / "browser" / "camoufox-bin"
            self.assertEqual(output.read_bytes(), b"binary")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(output.parent.stat().st_mode), 0o755)

    def test_zip_traversal_symlink_duplicate_and_size_are_rejected(self):
        cases = ("traversal", "symlink", "duplicate", "size")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                archive_path = root / "bad.zip"
                target = root / "target"
                target.mkdir()
                with zipfile.ZipFile(archive_path, "w") as archive:
                    if case == "traversal":
                        archive.writestr("../escape", b"x")
                    elif case == "symlink":
                        info = zipfile.ZipInfo("link")
                        info.external_attr = (stat.S_IFLNK | 0o777) << 16
                        archive.writestr(info, b"target")
                    elif case == "duplicate":
                        archive.writestr("same", b"one")
                        archive.writestr("same", b"two")
                    else:
                        archive.writestr("large", b"x" * 20)
                with self.assertRaises(safe_extract.ArchiveError):
                    safe_extract.extract_zip(archive_path, target, 10 if case == "size" else 1024)
                self.assertFalse((root / "escape").exists())

    def test_tar_rejects_links_and_extracts_regular_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            good = root / "good.tar.gz"
            target = root / "target"
            target.mkdir()
            with tarfile.open(good, "w:gz") as archive:
                info = tarfile.TarInfo("package/module.py")
                data = b"VALUE = 1\n"
                info.size = len(data)
                info.mode = 0o644
                archive.addfile(info, io.BytesIO(data))
            safe_extract.extract_tar(good, target, 1024)
            self.assertEqual((target / "package" / "module.py").read_bytes(), data)

            bad = root / "bad.tar.gz"
            empty = root / "empty"
            empty.mkdir()
            with tarfile.open(bad, "w:gz") as archive:
                link = tarfile.TarInfo("package/link")
                link.type = tarfile.SYMTYPE
                link.linkname = "/etc/passwd"
                archive.addfile(link)
            with self.assertRaises(safe_extract.ArchiveError):
                safe_extract.extract_tar(bad, empty, 1024)


if __name__ == "__main__":
    unittest.main()
