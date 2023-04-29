"""CSC110 Fall 2022 Assignment 4, Part 4: Number Theory, Cryptography, and Algorithm Running Time Analysis

Instructions (READ THIS FIRST!)
===============================

This Python module contains the functions you should complete for Part 4 of this assignment.

Copyright and Usage Information
===============================

This file is provided solely for the personal and private use of students
taking CSC110 at the University of Toronto St. George campus. All forms of
distribution of this code, whether as given or with any changes, are
expressly prohibited. For more information on copyright for CSC110 materials,
please consult our Course Syllabus.

This file is Copyright (c) 2022 David Liu and Tom Fairgrieve
"""
from typing import Callable

from python_ta.contracts import check_contracts

# Uncomment the following line if you would like to reuse your work from Part 3 in this file.
import a4_part3


###############################################################################
# Part (a): Introduction
###############################################################################
@check_contracts
def rsa_sign_simple(private_key: tuple[int, int, int],
                    message: str) -> int:
    """Return a digital signature for the given message.

    NOTE: the message digest is computed as simply len(message) % n, where
    n = p * q from the private key.

    Preconditions:
    - private_key is a tuple (p, q, d) as generated by the RSA key generation phase
    - message != ''

    NOTE: Part (a) asks you to add one specific doctest example here. Don't overlook this!

    >>> rsa_sign_simple((23,59,115), 'Cryptography is cool')
    1183
    """
    p, q, d = private_key[0], private_key[1], private_key[2]
    n = p * q

    digest = len(message) % n

    return pow(digest, d, n)


@check_contracts
def rsa_verify_simple(public_key: tuple[int, int],
                      message: str,
                      signature: int) -> bool:
    """Return whether the given signature matches the given message.

    NOTE: the message digest is computed as simply len(message) % n, where n is
    the modulus from the public key.

    Preconditions:
    - public_key is a tuple (n, e) as generated by the RSA key generation phase
    - message != ''

    NOTE: Part (a) asks you to add two specific doctest examples here. Don't overlook this!

    >>> rsa_verify_simple((1357,1043), 'Cryptography is cool', 1183)
    True
    >>> rsa_verify_simple((1357,1043), 'Cryptography is cool', 124)
    False
    """
    n, e = public_key[0], public_key[1]

    digest = len(message) % n

    return pow(signature, e, n) == digest


def test_collision_simple() -> None:
    """Test for a collision of digital signatures when using our simple length-based digest.

    You should complete this test case ONLY by filling in the ..., and not modifying the
    other parts of the test code. That said, make sure to read the full test code to understand
    what is being tested.
    """
    private_key = (23, 59, 115)
    m1 = 'Cryptography is cool'

    m2 = 'Cryptography is fun!'

    # Check that the two messages are distinct
    assert m1 != m2

    # Check that thetwo messages generate the same signature
    assert rsa_sign_simple(private_key, m1) == rsa_sign_simple(private_key, m2)


@check_contracts
def find_collision_simple(message: str) -> str:
    """Return a new message, not equal to the given message, that can be verified using the same signature
    when using the RSA digital signature scheme implemented in rsa_sign_simple/rsa_verify_simple.

    Preconditions:
    - message != ''

    >>> example_private_key = (23, 59, 115)
    >>> example_public_key = (1357, 1043)
    >>> example_message = 'Cryptography is cool'
    >>> example_signature = rsa_sign_simple(example_private_key, example_message)
    >>> new_message = find_collision_simple(example_message)
    >>> # The returned message can't be the same as the original
    >>> new_message == example_message
    False
    >>> # The new message and signature can be verified using the same signature
    >>> rsa_verify_simple(example_public_key, new_message, example_signature)
    True
    """
    new_message = message.replace(message[0], '!')
    return new_message


###############################################################################
# Part (b): Generalizing the message digests
###############################################################################
@check_contracts
def rsa_sign(private_key: tuple[int, int, int],
             compute_digest: Callable[[str], int],
             message: str) -> int:
    """Return a digital signature for the given message.

    Identical to rsa_sign_simple, except the message digest is computed by calling
    compute_digest(message) instead of just len(message).

    Preconditions:
    - private_key is a tuple (p, q, d) as generated by the RSA key generation phase
    - message satisfies all preconditions of compute_digest
    - message != ''

    The following doctest example should be very similar to the one you wrote for rsa_sign_simple.
    We're passing in the len function, so that when rsa_sign is called, compute_digest and len are
    aliases, so calling compute_digest(message) in the function body is equivalent to calling
    len(message).

    >>> rsa_sign((23, 59, 115), len, 'Cryptography is cool')
    1183
    """
    p, q, d = private_key[0], private_key[1], private_key[2]
    n = p * q

    digest = compute_digest(message) % n

    return pow(digest, d, n)


@check_contracts
def rsa_verify(public_key: tuple[int, int],
               compute_digest: Callable[[str], int],
               message: str,
               signature: int) -> bool:
    """Return whether the given signature matches the given message.

    Identical to rsa_verify_simple, except the message digest is computed by calling
    compute_digest(message) instead of just len(message).

    Preconditions:
    - public_key is a tuple (n, e) as generated by the RSA key generation phase
    - message satisfies all preconditions of compute_digest
    - message != ''

    The following doctest example should be very similar to the first one you wrote for rsa_verify_simple.

    >>> rsa_verify((1357, 1043), len, 'Cryptography is cool', 1183)
    True
    """
    n, e = public_key[0], public_key[1]

    digest = compute_digest(message) % n

    return pow(signature, e, n) == digest


@check_contracts
def len_times_sum(message: str) -> int:
    """Return the digest computed for the message by multiplying its length by the sum of its ord values.

    Preconditions:
    - message != ''
    """

    digest = len(message) * sum([ord(i) for i in message])
    return digest


@check_contracts
def ascii_to_int(message: str) -> int:
    """Return the digest computed for the message by interpreting it as a base-128 integer representation.

    Preconditions:
    - message != ''
    - all({ord(c) < 128 for c in message})

    NOTE: you *may* reuse code from Part 3 by uncommenting the "import a4_part3" statement to the top of
    this file.
    """

    digits = []
    for i in message:
        digits += [ord(i)]

    digest = a4_part3.base128_to_int(digits)
    return digest


def test_collision_len_times_sum() -> None:
    """Test for a collision of digital signatures when using our len_times_sum digest.

    You should complete this test case ONLY by filling in the ..., and not modifying the
    other parts of the test code. But make sure to read the full test case to understand
    what it is testing.
    """
    private_key = (23, 59, 115)
    m1 = 'hello'
    m2 = 'olleh'

    assert m1 != m2
    assert rsa_sign(private_key, len_times_sum, m1) == rsa_sign(private_key, len_times_sum, m2)


@check_contracts
def find_collision_len_times_sum(message: str) -> str:
    """Return a new message, not equal to the given message, that can be verified using the same signature
    when using the RSA digital signature scheme with the len_times_sum message digest.

    Preconditions:
    - len(message) >= 2
    """

    list_message = []
    for i in message:
        list_message += [i]

    list.reverse(list_message)
    new_message = ''.join(list_message)

    return new_message


def test_collision_ascii_to_int() -> None:
    """Test for a collision of digital signatures when using our ascii_to_int digest.

    You should complete this test case ONLY by filling in the ..., and not modifying the
    other parts of the test code. But make sure to read the full test case to understand
    what it is testing.

    Your chosen string for m2 must satisfy the following properties:
        - it can only contain ASCII characters
        - it CANNOT contain any chr(0) characters (and in particular, you may
          not simply add some leading chr(0) characters to the start of the string)
    """
    private_key = (23, 59, 115)
    m1 = 'hello'
    m2 = '\x03*'

    # Additional checks for m2
    assert all({ord(c) < 128 for c in m2})
    assert ord(m2[0]) > 0

    # The standard collision checks
    assert m1 != m2
    assert rsa_sign(private_key, ascii_to_int, m1) == rsa_sign(private_key, ascii_to_int, m2)


@check_contracts
def find_collision_ascii_to_int(public_key: tuple[int, int], message: str) -> str:
    """Return a new message, distinct from the given message, that can be verified using the same signature,
    when using the RSA digital signature scheme with the ascii_to_int message digest and the given public_key.

    The returned message must contain only ASCII characters, and cannot contain any leading chr(0) characters.

    Preconditions:
    - signature was generated from message using the algorithm in rsa_sign and digest len_times_sum,
      with a valid RSA private key
    - len(message) >= 2
    - ord(message[0]) > 0

    NOTES:
        - Unlike the other two "find_collision" functions, this function takes in the public key
          used to generate signatures. Use it!
        - You may NOT simply add leading chr(0) characters to the message string.
          (While this does correctly produces a collision, we want you to think a bit harder
          to come up with a different approach.)
        - You may find it useful to review Part 1, Question 1.
    """

    nums = [ord(i) for i in message]
    print(nums)
    num_in_128 = a4_part3.base128_to_int(nums)
    print(num_in_128)
    new_digest = num_in_128 % public_key[0]
    print(new_digest)
    values = a4_part3.int_to_base128(new_digest)
    print(values)
    letters = [chr(i) for i in values]
    print(letters)
    return ''.join(letters)


if __name__ == '__main__':
    import doctest

    doctest.testmod(verbose=True)

    import pytest

    pytest.main(['a4_part4.py', '-v'])

    # When you are ready to check your work with python_ta, uncomment the following lines.
    # (In PyCharm, select the lines below and press Ctrl/Cmd + / to toggle comments.)
    import python_ta
    python_ta.check_all(config={
        'max-line-length': 120,
        'disable': ['use-a-generator'],
        'extra-imports': ['a4_part3']
    })
