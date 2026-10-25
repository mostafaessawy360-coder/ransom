import os
import tempfile
import unittest
import zipfile
from pathlib import Path

from detector import entropy, samples
from detector.analyzer import CLEAN, HIGH_RISK, SUSPICIOUS, Analyzer
from detector.monitor import Monitor
from detector.scanner import scan


class EntropyTests(unittest.TestCase):
    def test_constant_data_has_zero_entropy(self):
        self.assertEqual(entropy.shannon_entropy(b"\x00" * 5000), 0.0)

    def test_random_data_is_near_8(self):
        self.assertGreater(entropy.shannon_entropy(os.urandom(65536)), 7.9)

    def test_text_is_low(self):
        self.assertLess(entropy.shannon_entropy(samples.LOREM.encode()), 5.0)

    def test_random_is_uniform_text_is_not(self):
        self.assertTrue(entropy.looks_uniform(os.urandom(65536)))
        self.assertFalse(entropy.looks_uniform(samples.LOREM.encode()))

    def test_is_text(self):
        self.assertTrue(entropy.is_text("hello world\n".encode()))
        self.assertTrue(entropy.is_text("مرحبا بالعالم " .encode("utf-8") * 50))
        self.assertFalse(entropy.is_text(os.urandom(4096)))


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.az = Analyzer()

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name, data):
        p = self.dir / name
        p.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
        return p

    def test_plain_text_is_clean(self):
        self.assertEqual(self.az.analyze(self.write("a.txt", samples.LOREM)).verdict, CLEAN)

    def test_random_docx_is_high_risk(self):
        r = self.az.analyze(self.write("a.docx", os.urandom(30000)))
        self.assertEqual(r.verdict, HIGH_RISK)
        self.assertTrue(r.has_rule("header_destroyed_high_entropy"))

    def test_real_docx_is_clean(self):
        p = self.dir / "ok.docx"
        with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("word/document.xml", samples.LOREM)
        self.assertEqual(self.az.analyze(p).verdict, CLEAN)

    def test_random_txt_is_high_risk(self):
        r = self.az.analyze(self.write("a.txt", os.urandom(20000)))
        self.assertEqual(r.verdict, HIGH_RISK)

    def test_valid_png_with_random_pixels_is_clean(self):
        self.assertEqual(self.az.analyze(self.write("a.png", samples._png())).verdict, CLEAN)

    def test_partial_encryption_detected(self):
        data = samples.LOREM.encode()[:16384].ljust(16384) + os.urandom(32768)
        r = self.az.analyze(self.write("a.txt", data))
        self.assertNotEqual(r.verdict, CLEAN)
        self.assertTrue(r.has_rule("partially_encrypted"))

    def test_known_extension_with_random_content_is_high_risk(self):
        r = self.az.analyze(self.write("a.lockbit", os.urandom(18000)))
        self.assertEqual(r.verdict, HIGH_RISK)

    def test_appended_extension_and_contact_tag(self):
        r = self.az.analyze(self.write("pic.jpg.id-1A2B3C4D.[x@y.com].zzq", os.urandom(20000)))
        self.assertEqual(r.verdict, HIGH_RISK)

    def test_ransom_note_content_flagged(self):
        r = self.az.analyze(self.write("info.txt", samples.NOTE))
        self.assertNotEqual(r.verdict, CLEAN)
        self.assertTrue(r.has_rule("ransom_note_content"))

    def test_single_weak_phrase_is_not_flagged(self):
        r = self.az.analyze(self.write("crypto.txt", "How to generate a decryption key with openssl.\n"))
        self.assertEqual(r.verdict, CLEAN)

    def test_ignore_ext(self):
        az = Analyzer(ignore_exts=["dat"])
        self.assertEqual(az.analyze(self.write("a.dat", os.urandom(20000))).verdict, CLEAN)

    def test_empty_and_missing_files(self):
        self.assertEqual(self.az.analyze(self.write("e.txt", b"")).verdict, CLEAN)
        self.assertIsNotNone(self.az.analyze(self.dir / "missing.txt").error)

    def test_large_file_uses_three_samples(self):
        data = samples.LOREM.encode() * 400            # ~ 100 KB text
        r = self.az.analyze(self.write("big.txt", data))
        self.assertEqual(r.verdict, CLEAN)


class ScannerTests(unittest.TestCase):
    def test_clean_vs_infected_samples(self):
        with tempfile.TemporaryDirectory() as tmp:
            clean, infected = samples.generate_samples(tmp)
            good = scan(str(clean), workers=1)
            self.assertEqual(good.counts[HIGH_RISK] + good.counts[SUSPICIOUS], 0, good.flagged)
            bad = scan(str(infected), workers=2)
            self.assertEqual(bad.files_scanned, 13)
            self.assertGreaterEqual(bad.counts[HIGH_RISK] + bad.counts[SUSPICIOUS], 12)
            self.assertTrue(any("lockbit" in a for a in bad.alerts), bad.alerts)
            self.assertTrue(any("different folders" in a for a in bad.alerts), bad.alerts)


class MonitorTests(unittest.TestCase):
    def test_burst_of_encrypted_files_raises_alert(self):
        with tempfile.TemporaryDirectory() as tmp:
            mon = Monitor(tmp, alert_files=5, window=60)
            mon.prime()
            (Path(tmp) / "ok.txt").write_text(samples.LOREM)
            self.assertEqual(mon.poll_once(now=1000.0), [])
            for i in range(6):
                (Path(tmp) / f"f{i}.docx").write_bytes(os.urandom(20000))
            events = mon.poll_once(now=1001.0)
            self.assertEqual(sum(e.level == "WARN" for e in events), 6)
            self.assertTrue(any(e.level == "ALERT" for e in events))


if __name__ == "__main__":
    unittest.main()
