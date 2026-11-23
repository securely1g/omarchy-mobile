# SPDX-License-Identifier: MIT
"""Offline prepared installer regression on a disposable ext4 image and fake transport."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("prepared", ROOT / "tools/lib/prepared_image.py")
prepared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepared)
SERIAL = "test-fixture"


def key(octet):
    blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes([octet]) * 32
    return "ssh-ed25519 " + base64.b64encode(blob).decode()


def newc(name, payload=b"", mode=0o100644):
    fields = [1, mode, 0, 0, 1, 0, len(payload), 0, 0, 0, 0, len(name) + 1, 0]
    header = b"070701" + b"".join(f"{value:08x}".encode() for value in fields) + name.encode() + b"\x00"
    return header + bytes(-len(header) % 4) + payload + bytes(-len(payload) % 4)


def boot_image(archive):
    compressed = subprocess.run(["lz4", "-l", "-q", "-c"], input=archive, capture_output=True, check=True).stdout
    header, table = bytearray(4096), bytearray(4096)
    header[:8] = b"VNDRBOOT"
    struct.pack_into("<5I", header, 8, 4, 4096, 0, 0, len(compressed))
    struct.pack_into("<I", header, 2096, 2128)
    struct.pack_into("<4I", header, 2112, 108, 1, 108, 0)
    struct.pack_into("<II", table, 0, len(compressed), 0)
    return header + compressed + bytes(-len(compressed) % 4096) + table


TOOLS = ("debugfs", "mkfs.ext4", "dumpe2fs", "e2fsck", "zstd", "openssl", "lz4", "cpio")
MISSING = [name for name in TOOLS if not shutil.which(name)]


@unittest.skipIf(MISSING, "missing test tools: " + ", ".join(MISSING))
class Install(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.images = self.root / "images"
        self.images.mkdir()
        self.archive = newc("init", b"init", 0o100755) + newc("TRAILER!!!")
        (self.images / "vendor_kernel_boot.img").write_bytes(boot_image(self.archive))
        (self.images / "boot.img").write_bytes(b"boot")
        self.repo = self.root / "repo"
        (self.repo / "tools/lib").mkdir(parents=True)
        shutil.copy2(ROOT / "tools/install-phone", self.repo / "tools/install-phone")
        shutil.copy2(ROOT / "tools/lib/prepared_image.py", self.repo / "tools/lib/prepared_image.py")
        descriptor = self.repo / "device/testdev/device.conf"
        descriptor.parent.mkdir(parents=True)
        descriptor.write_text('CODENAME=testdev\nSOC_IDS=1\nBOOT_IMAGES="boot vendor_kernel_boot"\nUFS_RW="boot_b vendor_kernel_boot_b userdata"\n')
        self.mock = self.root / "mock"
        self.mock.write_text("""#!/usr/bin/env python3
from pathlib import Path
import sys
args = sys.argv[1:]
with (Path(__file__).parent/'calls').open('a') as log: print(' '.join(args),file=log)
if args == ['devices']: print('test-fixture\\tfastboot')
elif args == ['-s','test-fixture','getvar','all']:
 print('product:testdev\\nunlocked:yes\\ncurrent-slot:b\\nversion-bootloader:fixture\\npartition-size:boot_b:0x4000000\\npartition-size:vendor_kernel_boot_b:0x4000000\\npartition-size:userdata:0x4000000')
else: sys.exit(99)
""")
        self.mock.chmod(0o700)
        self.raw = self.root / "root.img"
        self.zipped = self.root / "root.img.zst"
        self.receipt_file = self.root / "receipt.json"
        self.fs = self.root / "fs"
        self.install_fixture()

    def contents(self, name, data):
        p = self.fs / name.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode())

    def install_fixture(self):
        ids = [f"test{i}.desktop" for i in range(5)]
        data = {"/usr/share/omarch-phone-image/accounts.json": {"daily": "daily", "parent": "parent", "synthetic_test_accounts": True, "production_enrollment": False},
                "/etc/omamobile/image-policy.json": {"dailyUser": "daily", "allowedDesktopIds": ids},
                "/etc/omamobile/image-profile.json": {"allowedDesktopIds": ids},
                "/etc/omamobile/parent-screen-enrollment.json": {"device": "test-phone"},
                "/var/lib/omarch-phone-screen-time/policy.json": {"device": "test-phone"}}
        for name in prepared.REQUIRED_FILES:
            self.contents(name, "reviewed fixture\n")
        for name, value in data.items():
            self.contents(name, json.dumps(value))
        self.contents("/etc/passwd", "daily:x:1000:1000::/home/daily:/bin/bash\nparent:x:1001:1001::/home/parent:/bin/bash\n")
        self.contents("/etc/group", "wheel:x:10:parent\n")
        self.contents("/home/parent/.ssh/authorized_keys", key(1) + " fixture\n")
        self.contents("/etc/sudoers.d/90-parent-admin", "parent ALL=(ALL:ALL) NOPASSWD: ALL\n")
        self.contents("/etc/sudoers.d/zz-parent-managed-daily", "daily ALL=(ALL:ALL) !ALL\n")
        self.contents("/usr/bin/bash", b"\x7fELF\x02\x01" + bytes(12) + b"\xb7\x00")
        self.contents("/etc/omamobile/boot-update.conf", "AUTO_WRITE=no\n")
        self.contents("/root/.ssh/authorized_keys", key(4) + "\n")
        self.seal()

    def seal(self):
        with self.raw.open("wb") as f:
            f.truncate(12 * 1024 * 1024)
        subprocess.run(["mkfs.ext4", "-q", "-F", "-L", "omamobile-root", "-d", self.fs, self.raw], check=True)
        subprocess.run(["zstd", "-fq", self.raw, "-o", self.zipped], check=True)
        sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
        self.receipt = {"version": 1, "purpose": "rehearsal", "device": "testdev", "policy_device": "test-phone",
                        "serial_sha256": hashlib.sha256(SERIAL.encode()).hexdigest(), "parent_public_key": key(1),
                        "recovery_public_key": key(2), "root_sha256": sha(self.zipped), "raw_sha256": sha(self.raw),
                        "boot_sha256": {p.stem: sha(p) for p in self.images.glob("*.img")},
                        "managed_files": {p: sha(self.fs / p.lstrip("/")) for p in prepared.REQUIRED_FILES}}

    def command(self, *args):
        self.receipt_file.write_text(json.dumps(self.receipt))
        self.receipt_file.chmod(0o600)
        return [self.repo / "tools/install-phone", "--prepared-image", self.receipt_file, "--serial", SERIAL,
                "--device", "testdev", "--rootfs", self.zipped, "--images", self.images, "--work", self.root / "work",
                "--reinstall", *args]

    def run_installer(self, *args):
        return subprocess.run(self.command(*args), env={**os.environ, "FASTBOOT": str(self.mock)},
                              input="testdev\n", capture_output=True, text=True)

    def test_prepared_dry_run(self):
        verified = self.run_installer("--verify-only")
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertFalse((self.root / "calls").exists())
        env = {**os.environ, "FASTBOOT": str(self.mock), "OMAMOBILE_INSTALL_GUIDED": "1"}
        with subprocess.Popen(self.command("--dry-run"), env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True) as child:
            lines = []
            try:
                for line in child.stdout:
                    lines.append(line)
                    if "the bootloader, radio, persist, efs, modem and devinfo are not touched" in line:
                        directory, = (self.root / "work").glob("prepared.*")
                        staged = directory / "root.img"
                        if not staged.exists():
                            subprocess.run(["simg2img", directory / "root.simg", staged], check=True)
                        self.assertEqual(staged.read_bytes(), self.raw.read_bytes())
                        child.stdin.write("testdev\n")
                        child.stdin.flush()
                self.assertEqual(child.wait(timeout=10), 0, "".join(lines))
            finally:
                if child.poll() is None:
                    child.kill()
        transcript = "".join(lines)
        self.assertIn("personalized recovery boot SHA256:", transcript)
        self.assertIn("Dry run done", transcript)
        self.assertEqual((self.root / "calls").read_text().splitlines(), ["devices", "-s test-fixture getvar all"])
        self.assertEqual(list((self.root / "work").iterdir()), [])
        self.assertNotIn("About the phone's owner", transcript)

    def test_rehearsal_cannot_write_and_synthetic_cannot_be_relabelled(self):
        self.assertIn("only for verify-only or dry-run", self.run_installer().stderr)
        self.receipt.update(purpose="production", receiver_public_key=key(3))
        self.assertIn("replacement of synthetic credentials", self.run_installer().stderr)
        self.assertFalse((self.root / "calls").exists())

    def test_production_requires_a_ready_independent_receiver(self):
        marker = "/usr/share/omarch-phone-image/accounts.json"
        record = json.loads((self.fs / marker.lstrip("/")).read_text())
        record.update(synthetic_test_accounts=False, production_enrollment=True)
        self.contents(marker, json.dumps(record))
        self.contents("/root/.ssh/authorized_keys", key(2) + "\n")
        with (self.fs / "etc/passwd").open("a") as f:
            f.write("phone-policy:x:400:400::/var/lib/omarch-phone-screen-time/ssh:/bin/bash\n")
        self.contents("/etc/shadow", "daily:$6$dummy:1::::::\nphone-policy:!:1::::::\n")
        self.contents("/etc/sudoers.d/90-phone-screen-policy",
                      "phone-policy ALL=(root) NOPASSWD: /usr/local/libexec/omarch-phone-screen-time receive\n")
        path = "/var/lib/omarch-phone-screen-time/ssh-enrollment/record.json"
        receiver = {"state": "ready", "device": "test-phone", "publicKey": key(3)}
        self.contents(path, json.dumps(receiver))
        self.contents("/var/lib/omarch-phone-screen-time/ssh/.ssh/authorized_keys",
                      'restrict,command="/usr/bin/sudo -n /usr/local/libexec/omarch-phone-screen-time receive" ' + key(3) + "\n")
        self.seal()
        self.receipt.update(purpose="production", receiver_public_key=key(3))
        check = self.run_installer("--verify-only")
        self.assertEqual(check.returncode, 0, check.stderr)
        self.receipt["receiver_public_key"] = key(1)
        self.assertIn("independent", self.run_installer("--verify-only").stderr)
        receiver["device"] = "other-phone"
        self.contents(path, json.dumps(receiver))
        self.seal()
        self.receipt.update(purpose="production", receiver_public_key=key(3))
        self.assertIn("not enrolled", self.run_installer("--verify-only").stderr)
        self.assertFalse((self.root / "calls").exists())

    def test_userdata_capacity_blocks_preparation(self):
        self.mock.write_text(self.mock.read_text().replace("partition-size:userdata:0x4000000", "partition-size:userdata:0x100"))
        self.assertIn("exceeds userdata capacity", self.run_installer("--dry-run").stderr)
        self.assertEqual((self.root / "calls").read_text().splitlines(), ["devices", "-s test-fixture getvar all"])

    def test_wrong_identity_protected_bytes_or_missing_boot_checksum(self):
        for field, value, message in (("serial_sha256", "0" * 64, "serial differs"),
                                       ("policy_device", "another-device", "different device"),
                                       ("parent_public_key", key(2), "maintenance authorization differs"),
                                       ("raw_sha256", "f" * 64, "ext4 digest differs"),
                                       ("root_sha256", "f" * 64, "compressed root digest differs"),
                                       ("boot_sha256", {"boot": "f" * 64}, "exact boot and managed file set")):
            with self.subTest(field=field):
                original = self.receipt[field]
                self.receipt[field] = value
                self.assertIn(message, self.run_installer("--dry-run").stderr)
                self.receipt[field] = original
        self.receipt["managed_files"]["/etc/pam.d/omarchy-lock-password"] = "f" * 64
        self.assertIn("file digest differs", self.run_installer("--verify-only").stderr)
        self.assertFalse((self.root / "calls").exists())

    def test_descriptor_and_existing_firstboot_answers_are_checked(self):
        (self.images / "DEVICE").write_text("wrong-device\n")
        self.assertIn("not testdev", self.run_installer("--verify-only").stderr)
        (self.images / "DEVICE").write_text("testdev\n")
        self.contents("/etc/omamobile/firstboot.conf", "USERNAME=bootstrap\n")
        self.seal()
        self.assertIn("active firstboot answers", self.run_installer("--verify-only").stderr)
        self.assertFalse((self.root / "calls").exists())

    def test_hidden_second_cpio_key_is_rejected(self):
        extra = newc("./root/./.ssh/authorized_keys", b"unexpected", 0o100600) + newc("TRAILER!!!")
        boot = self.images / "vendor_kernel_boot.img"
        boot.write_bytes(boot_image(self.archive + bytes(-len(self.archive) % 512) + extra))
        self.receipt["boot_sha256"]["vendor_kernel_boot"] = hashlib.sha256(boot.read_bytes()).hexdigest()
        self.assertIn("unapproved or missing rescue SSH", self.run_installer("--verify-only").stderr)
        self.assertFalse((self.root / "calls").exists())


if __name__ == "__main__":
    unittest.main()
