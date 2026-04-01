import pytest

from src.analysis.entropy import shannon_entropy, scan_entropy, find_sjis_clusters

def test_shannon_entropy_all_zeros():
    data = b"\x00" * 100
    entropy = shannon_entropy(data)
    assert entropy == 0.0

def test_shannon_entropy_random():
    import os
    data = os.urandom(100)
    entropy = shannon_entropy(data)
    # Random bytes should have entropy close to maximum (log2(256) = 8.0)
    assert 6.0 <= entropy <= 8.0

def test_scan_entropy():
    # 256 bytes of zero (plaintext), then 256 bytes of random (compressed)
    import os
    zeros = b"\x00" * 256
    random_bytes = os.urandom(256)
    data = zeros + random_bytes

    regions = scan_entropy(data, window_size=256, step_size=256)
    
    assert len(regions) == 2
    assert regions[0].region_type.value == "plaintext"
    assert regions[1].region_type.value == "compressed"

def test_find_sjis_clusters():
    # A natural sentence properly detected by Chardet
    sjis_text = "これはテストです。Shift-JISのテキストを検出できるか確認しています。".encode("shift_jis") + b"\x00"
    
    # Pad to make it big enough
    padded_sjis = b"\xFF" * 10 + sjis_text * 3 + b"\xFF" * 10
    
    clusters = find_sjis_clusters(padded_sjis, min_cluster_size=6, chardet_confidence=0.5)
    
    assert len(clusters) == 3
    for cluster in clusters:
        assert cluster.decoded_preview.startswith("これは")
