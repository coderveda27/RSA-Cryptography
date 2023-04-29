"""CSC110 Fall 2022 Assignment 4, Part 3: Number Theory, Cryptography, and Algorithm Running Time Analysis

Instructions (READ THIS FIRST!)
===============================

This Python module contains the functions you should complete for Part 3 of this assignment.

Copyright and Usage Information
===============================

This file is provided solely for the personal and private use of students
taking CSC110 at the University of Toronto St. George campus. All forms of
distribution of this code, whether as given or with any changes, are
expressly prohibited. For more information on copyright for CSC110 materials,
please consult our Course Syllabus.

This file is Copyright (c) 2022 David Liu and Tom Fairgrieve
"""
# You may uncomment this statement to import the math module in this file
import math

from python_ta.contracts import check_contracts


###############################################################################
# Part (a): From strings to numbers
###############################################################################
@check_contracts
def base128_to_int(digits: list[int]) -> int:
    """Return the integer represented by the given base-128 representation.

    The input list has the units (128 ** 0) digit at the LAST index.

    Preconditions:
        - digits != []
        - all({0 <= d < 128 for d in digits})

    >>> base128_to_int([1])
    1
    >>> base128_to_int([3, 2, 4])  # 3 * (128 ** 2) + 2 * (128 ** 1) + 4 * (128 ** 0)
    49412
    >>> base128_to_int([72, 101, 108, 108, 111])
    19540948591

    NOTE: this function can be implemented by either a for loop or a comprehension.
    For practice, we strongly recommend trying both implementations.
    """
    value_so_far = 0
    length = len(digits)

    for i in range(0, length):
        value_so_far += digits[i] * (pow(128, (length - (i + 1))))
    return value_so_far


@check_contracts
def int_to_base128(n: int) -> list[int]:
    """Return the base-128 representation of the given number.

    The returned list has the units (128 ** 0) digit at the LAST index.
    The returned list should not have any leading zeros (i.e., the first element should be > 0).

    Preconditions:
    - n >= 1

    >>> int_to_base128(1)
    [1]
    >>> int_to_base128(49412)
    [3, 2, 4]

    HINTS: Here are two possible (ideas for) algorithms to solve this problem.
    You may use a different approach, as long as you use only programming elements and techniques
    allowed for this assignment. In particular, "recursion" is not permitted.

    APPROACH 1 ("big to small"):
        Start by computing the largest power of 128 that's less than n, and then compute the
        quotient (n // (128 ** ___)); that gives you the first element of the list.
        Update n in some way, and then repeat. You will find the math.log function useful.

    APPROACH 2 ("small to big"):
        Compute the remainder n % 128. That gives you the units digit (last element of the list).
        Update n in some way, and then repeat.
    """
    lst = [n]
    while n > 1:
        n = n // 128
        if n > 0:
            lst.append(n)

    new_lst = []
    for i in range(0, len(lst)):
        new_lst.insert(len(lst) - (i + len(lst)), lst[i])

    new_lst_values = [k % 128 for k in new_lst]
    return new_lst_values


###############################################################################
# Part (b): Encrypting and decrypting blocks
###############################################################################
@check_contracts
def rsa_encrypt_block(public_key: tuple[int, int], plaintext: str) -> list[int]:
    """Encrypt the given plaintext using the recipient's public key.

    Preconditions:
        - public_key is a valid RSA public key (n, e)
        - public_key[0] >= 128
        - all({ord(c) < 128 for c in plaintext})
        - plaintext != ''
        - len(plaintext) is divisibile by the block length

    NOTES:

    1. Use the math.pow function to compute a modular exponentiation, not ** and %.
       math.pow is much more efficient for larger numbers!
    2. You may find it useful to use range with THREE arguments, e.g. range(0, 10, 2).
       Experiment with this in the Python console!
    """

    n = public_key[0]
    e = public_key[1]

    block_length = math.floor(math.log(n, 128))

    blocks = [plaintext[i:i + block_length] for i in range(0, len(plaintext), block_length)]

    int_blocks = [[ord(i) for i in block] for block in blocks]

    blocks_base128 = [base128_to_int(block) for block in int_blocks]

    encrypted = []
    for num in blocks_base128:
        encrypted += [pow(num, e, n)]
    return encrypted


@check_contracts
def rsa_decrypt_block(private_key: tuple[int, int, int], ciphertext: list[int]) -> str:
    """Decrypt the given ciphertext using the recipient's private key.

    Preconditions:
        - private_key is a valid RSA private key (p, q, d)
        - private_key[0] * private_key[1] >= 128
        - ciphertext != []
        - all({0 <= num < private_key[0] * private_key[1] for num in ciphertext})
    """

    p = private_key[0]
    q = private_key[1]
    d = private_key[2]

    n = p * q

    block_length = math.floor(math.log(n, 128))

    rsa_conversion = []
    for num in ciphertext:
        rsa_conversion += [pow(num, d, n)]

    int_values_converted = [int_to_base128(number) for number in rsa_conversion]

    for i in int_values_converted:
        while len(i) != block_length:
            i.insert(0, 0)

    chr_values = [[chr(new_num) for new_num in f] for f in int_values_converted]

    chr_values_1d = []
    for i in chr_values:
        for j in i:
            chr_values_1d.append(j)

    decrypted = ''.join(chr_values_1d)
    return decrypted


if __name__ == '__main__':
    import doctest

    doctest.testmod(verbose=True)

    # When you are ready to check your work with python_ta, uncomment the following lines.
    # (In PyCharm, select the lines below and press Ctrl/Cmd + / to toggle comments.)
    import python_ta

    python_ta.check_all(config={
        'max-line-length': 120,
        'disable': ['use-a-generator'],
        'extra-imports': ['math']
    })
