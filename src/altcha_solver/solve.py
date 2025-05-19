import hashlib
import asyncio
from typing import Optional

def solve_challenge(
        challenge: str,
        salt: str,
        algorithm: str = 'SHA-256',
        max_n: int = 1_000_000,
        start: int = 0
) -> Optional[int]:
    for n in range(start, max_n + 1):
        t = hash_challenge(salt, n, algorithm)
        if t == challenge:
            return n
    return None

async def solve_challenge_async(challenge: str, salt: str, algorithm: str = 'SHA-256',
                                max: int = 1_000_000, start: int = 0) -> int:
    return await asyncio.to_thread(solve_challenge, challenge, salt, algorithm, max, start)

def hash_challenge(salt: str, num: int, algorithm: str) -> str:
    try:
        algo = algorithm.lower().replace('-', '')
        hasher = hashlib.new(algo)
    except ValueError:
        raise ValueError(f"Unsupported hashing algorithm: {algorithm}")

    input_data = (salt + str(num)).encode('utf-8')
    hasher.update(input_data)
    return hasher.hexdigest()
