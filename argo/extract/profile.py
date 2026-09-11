import math
import re
from collections import Counter

from argo.schema import FileProfile

HEX_ID = re.compile(rb"_0x[0-9a-fA-F]{4,}")
LONG_ENCODED = re.compile(rb"[A-Za-z0-9+/=]{300,}")
ENTROPY_SAMPLE_BYTES = 1_000_000


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def profile_file(path: str, data: bytes) -> FileProfile:
    binary = is_binary(data)
    lines = data.split(b"\n")
    avg = len(data) / len(lines)
    hex_ids = 0 if binary else len(HEX_ID.findall(data))
    long_enc = 0 if binary else len(LONG_ENCODED.findall(data))
    return FileProfile(
        path=path,
        size=len(data),
        lines=len(lines),
        avg_line_len=round(avg, 1),
        max_line_len=max(len(line) for line in lines),
        entropy=round(shannon_entropy(data[:ENTROPY_SAMPLE_BYTES]), 2),
        hex_identifiers=hex_ids,
        long_encoded_strings=long_enc,
        minified=not binary and avg > 300,
        obfuscated=not binary and (hex_ids >= 20 or long_enc >= 3),
        binary=binary,
    )
