import pytest
import asyncio
from altcha_solver import solve_challenge, solve_challenge_async
from altcha_solver.solve import hash_challenge
import os


def create_test_challenge(number=None, max_number: int = 10_000, algorithm: str = 'SHA-256') -> dict:
    salt = os.urandom(8).hex()
    if number is None:
        number = os.urandom(1)[0] % (max_number + 1)
    challenge = hash_challenge(salt, number, algorithm)
    return {
        "salt": salt,
        "algorithm": algorithm,
        "challenge": challenge,
        "signature": "",  # Placeholder
        "number": number  # For internal use in tests
    }


def ab2hex(byte_data: bytes) -> str:
    return byte_data.hex()


def test_ab2hex():
    assert ab2hex(b'Hello world') == '48656c6c6f20776f726c64'


def test_hash_challenge():
    salt = 'randomstring'
    num = 123
    expected = hash_challenge(salt, num, 'SHA-256')
    assert expected == hash_challenge(salt, num, 'SHA-256')


def test_create_test_challenge():
    data = create_test_challenge(100)
    assert "algorithm" in data
    assert "salt" in data
    assert "challenge" in data
    assert data["signature"] == ""


def test_solve_challenge_correct():
    data = create_test_challenge(max_number=10)
    result = solve_challenge(data['challenge'], data['salt'], data['algorithm'])
    assert result is not None
    assert result == data["number"]


def test_mirror_altcha_test():
    data = create_test_challenge(number=10)
    result = solve_challenge(data['challenge'], data['salt'], data['algorithm'])
    assert result is not None
    assert result == 10


def test_solve_challenge_big():
    data = create_test_challenge(1_000_000)
    result = solve_challenge(data['challenge'], data['salt'], data['algorithm'])
    assert result is not None
    assert result == data["number"]


def test_real_challenge():
    # Real challenge:
    # {
    #     "algorithm": "SHA-256",
    #     "challenge": "a08ed07a5e2a1410156afd9d029afac60fa277d9fe509cddb27376f2e6ec82de",
    #     "maxnumber": 300000,
    #     "salt": "5b539cff62e9d57e6f63c4e0?expires=1747634775",
    #     "signature": "4a5684ab5fef0f564aadd5824a5326529b716220a1835cd29a2b560c36317d30"
    # }

    # Real result:
    # {
    #     "algorithm": "SHA-256",
    #     "challenge": "a08ed07a5e2a1410156afd9d029afac60fa277d9fe509cddb27376f2e6ec82de",
    #     "number": 169249,
    #     "salt": "5b539cff62e9d57e6f63c4e0?expires=1747634775",
    #     "signature": "4a5684ab5fef0f564aadd5824a5326529b716220a1835cd29a2b560c36317d30",
    #     "took": 728
    # }
    result = solve_challenge(
        challenge='a08ed07a5e2a1410156afd9d029afac60fa277d9fe509cddb27376f2e6ec82de',
        salt='5b539cff62e9d57e6f63c4e0?expires=1747634775',
        algorithm='SHA-256',
        max=300_000,
    )

    assert result is not None
    assert result == 169249


def test_solve_challenge_invalid_range():
    data = create_test_challenge(10)
    result = solve_challenge(data['challenge'], data['salt'], data['algorithm'], 20, 100)
    assert result is None


@pytest.mark.asyncio
async def test_solve_challenge_async_is_non_blocking():
    data = create_test_challenge(number=1_000_000)

    # 1) Kick off the solver but don't await it yet:
    long_task = asyncio.create_task(
        solve_challenge_async(data['challenge'], data['salt'], data['algorithm'])
    )

    # If the task was blocking, it would hang until it was done, meaning that by the time we reached this code it would be done
    # There is probably a better way to test this
    await asyncio.sleep(0.1)
    assert not long_task.done()

    await long_task
    assert long_task.done()


def test_solve_challenge_benchmark(benchmark):
    """
    Measure the performance of solve_challenge over a 0–10 000 search space.
    """
    max_n = 1_000_000
    data = create_test_challenge(max_number=max_n)

    def _run_solve():
        return solve_challenge(
            data["challenge"],
            data["salt"],
            data["algorithm"],
            max_n
        )

    # run the benchmark
    result = benchmark(_run_solve)

    # sanity check: solver still returns the correct number
    assert result == data["number"]
