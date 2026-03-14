"""Tests for LRU cache implementation."""

import pytest
from pathlib import Path

from src.data_parser import DataParser


class TestLRUCache:
    """Tests for OrderedDict-based LRU cache implementation."""

    def test_cache_initialization(self):
        """Test that cache is initialized with correct defaults."""
        parser = DataParser()
        assert len(parser._memory_cache) == 0
        assert parser._max_cache_size == 100
        assert isinstance(parser._memory_cache, dict)

    def test_cache_save_and_retrieve(self):
        """Test basic cache save and retrieve operations."""
        parser = DataParser()

        cache_key = parser._get_cache_key("test_data")
        test_value = {"result": "test_output"}

        parser._save_to_cache(cache_key, test_value, persist=False)
        retrieved = parser._get_from_cache(cache_key)

        assert retrieved == test_value

    def test_lru_eviction(self):
        """Test that least recently used items are evicted when cache is full."""
        parser = DataParser(cache_dir=None)
        parser._max_cache_size = 3  # Set small cache for testing

        # Use consistent data strings for cache key generation
        data_strings = ["data_0", "data_1", "data_2"]

        # Fill cache to capacity
        for i, data_str in enumerate(data_strings):
            cache_key = parser._get_cache_key(data_str)
            parser._save_to_cache(cache_key, f"value_{i}", persist=False)

        assert len(parser._memory_cache) == 3

        # Access item 1 and 2 (make them recently used)
        cache_key_1 = parser._get_cache_key(data_strings[1])
        cache_key_2 = parser._get_cache_key(data_strings[2])
        parser._get_from_cache(cache_key_1)
        parser._get_from_cache(cache_key_2)

        # Add new item (should evict key_0 as least recently used)
        new_data = "data_new"
        cache_key_new = parser._get_cache_key(new_data)
        parser._save_to_cache(cache_key_new, "value_new", persist=False)

        # Cache size should still be at max
        assert len(parser._memory_cache) == 3

        # key_0 should be evicted
        cache_key_0 = parser._get_cache_key(data_strings[0])
        assert parser._get_from_cache(cache_key_0) is None

        # New key and accessed keys should be present
        assert parser._get_from_cache(cache_key_1) == "value_1"
        assert parser._get_from_cache(cache_key_2) == "value_2"
        assert parser._get_from_cache(cache_key_new) == "value_new"

    def test_cache_miss(self):
        """Test that cache miss returns None."""
        parser = DataParser()

        cache_key = "nonexistent_key_hash"
        result = parser._get_from_cache(cache_key)

        assert result is None

    def test_cache_update_existing_key(self):
        """Test that updating an existing key works correctly."""
        parser = DataParser()

        cache_key = parser._get_cache_key("test_data")
        parser._save_to_cache(cache_key, "value_1", persist=False)
        parser._save_to_cache(cache_key, "value_2", persist=False)

        result = parser._get_from_cache(cache_key)
        assert result == "value_2"

    def test_persist_to_disk(self):
        """Test that persist=True saves to disk."""
        import tempfile
        import json

        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir)
            parser = DataParser(cache_dir=cache_dir)

            cache_key = parser._get_cache_key("test_data")
            test_value = {"result": "test_output"}

            parser._save_to_cache(cache_key, test_value, persist=True)

            # Check file was created
            cache_file = cache_dir / f"{cache_key}.json"
            assert cache_file.exists()

            # Verify file contents
            with open(cache_file, 'r') as f:
                saved_value = json.load(f)
                assert saved_value == test_value

    def test_disk_cache_fallback(self):
        """Test that disk cache is used when memory cache misses."""
        import tempfile
        import json

        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir)
            parser = DataParser(cache_dir=cache_dir)

            cache_key = parser._get_cache_key("test_data")
            test_value = {"result": "test_output"}

            # Save to disk only (clear memory cache)
            parser._save_to_cache(cache_key, test_value, persist=True)
            parser._memory_cache.clear()

            # Should retrieve from disk
            result = parser._get_from_cache(cache_key)
            assert result == test_value
