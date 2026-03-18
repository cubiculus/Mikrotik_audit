"""Unit tests for DataParser caching functionality."""

import unittest
import tempfile
import shutil
from pathlib import Path

from src.data_parser import DataParser
from src.config import CommandResult


class TestDataParserCaching(unittest.TestCase):
    """Test caching functionality in DataParser."""

    def setUp(self):
        """Set up test fixtures."""
        # Create temporary cache directory
        self.temp_dir = tempfile.mkdtemp()
        self.cache_dir = Path(self.temp_dir) / "cache"
        self.parser = DataParser(cache_dir=self.cache_dir)

    def tearDown(self):
        """Clean up test fixtures."""
        # Remove temporary directory
        if Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)

    def test_cache_key_generation(self):
        """Test that cache keys are generated consistently."""
        output = "/system resource print\nversion: 7.10"
        key1 = self.parser._get_cache_key(output)
        key2 = self.parser._get_cache_key(output)

        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), 64)  # SHA256 hash length

        # Different output should produce different keys
        different_output = "/system resource print\nversion: 7.11"
        key3 = self.parser._get_cache_key(different_output)
        self.assertNotEqual(key1, key3)

    def test_memory_cache(self):
        """Test memory cache functionality."""
        cache_key = "test_key"
        test_data = {"test": "data"}

        # Save to cache
        self.parser._save_to_cache(cache_key, test_data, persist=False)

        # Retrieve from cache
        cached_data = self.parser._get_from_cache(cache_key)

        self.assertEqual(cached_data, test_data)

    def test_disk_cache(self):
        """Test disk cache functionality."""
        cache_key = "test_disk_key"
        test_data = {"test": "disk_data"}

        # Save to disk cache
        self.parser._save_to_cache(cache_key, test_data, persist=True)

        # Check that file was created
        cache_file = self.cache_dir / f"{cache_key}.json"
        self.assertTrue(cache_file.exists())

        # Create new parser instance to test disk cache
        new_parser = DataParser(cache_dir=self.cache_dir)

        # Retrieve from disk cache
        cached_data = new_parser._get_from_cache(cache_key)

        self.assertEqual(cached_data, test_data)

    def test_cache_miss(self):
        """Test cache miss returns None."""
        cache_key = "non_existent_key"

        cached_data = self.parser._get_from_cache(cache_key)

        self.assertIsNone(cached_data)

    def test_memory_cache_clear(self):
        """Test that memory cache can be cleared."""
        cache_key = "test_clear_key"
        test_data = {"test": "clear_data"}

        # Save to memory cache
        self.parser._save_to_cache(cache_key, test_data, persist=False)

        # Verify it's in cache
        self.assertIn(cache_key, self.parser._memory_cache)

        # Clear cache
        self.parser._memory_cache.clear()

        # Verify it's gone from memory
        self.assertNotIn(cache_key, self.parser._memory_cache)

        # But still accessible via _get_from_cache (should check disk)
        cached_data = self.parser._get_from_cache(cache_key)
        self.assertIsNone(cached_data)  # Not on disk either

    def test_memory_cache_limit(self):
        """Test that memory cache has a limit of 100 entries with LRU eviction."""
        # Add 100 entries (at limit)
        for i in range(100):
            self.parser._save_to_cache(f"key_{i}", f"data_{i}", persist=False)

        self.assertEqual(len(self.parser._memory_cache), 100)

        # Add one more entry - should trigger LRU eviction
        self.parser._save_to_cache("key_1000", "data_1000", persist=False)

        # Should evict one entry (LRU) and add new one
        self.assertEqual(len(self.parser._memory_cache), 100)  # Still at limit
        self.assertIn("key_1000", self.parser._memory_cache)  # New entry present

    def test_build_network_overview_caching(self):
        """Test that build_network_overview uses caching."""
        # Create mock results
        results = [
            CommandResult(
                index=0,
                command="/system resource print",
                stdout="version: 7.10\nfree-memory: 512MiB",
                stderr="",
                has_error=False,
                duration=0.1
            ),
            CommandResult(
                index=1,
                command="/system identity print",
                stdout="name: TestRouter",
                stderr="",
                has_error=False,
                duration=0.1
            )
        ]

        # First call - should parse and cache
        overview1 = self.parser.build_network_overview(results)
        self.assertEqual(overview1.system_version, "7.10")
        self.assertEqual(overview1.system_identity, "TestRouter")

        # Second call - should use cache
        overview2 = self.parser.build_network_overview(results)
        self.assertEqual(overview2.system_version, "7.10")
        self.assertEqual(overview2.system_identity, "TestRouter")

        # Verify cache files were created
        cache_files = list(self.cache_dir.glob("*.json"))
        self.assertGreater(len(cache_files), 0)

    def test_cache_directory_creation(self):
        """Test that cache directory is created if it doesn't exist."""
        new_cache_dir = Path(self.temp_dir) / "new_cache"

        # Directory shouldn't exist
        self.assertFalse(new_cache_dir.exists())

        # Create parser with new directory
        _ = DataParser(cache_dir=new_cache_dir)

        # Directory should be created
        self.assertTrue(new_cache_dir.exists())
        self.assertTrue(new_cache_dir.is_dir())


if __name__ == '__main__':
    unittest.main()
