# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib_wallet.descriptors.descriptors.parse`.

An output descriptor is what a wallet is handed to watch somebody else's
keys: it arrives in a file, in an rpc argument or pasted, and parsing it
builds a tree of nested function calls, key expressions and derivation
paths out of text nobody signed. That is a recursive grammar over a
stranger's own input, which is what this harness is for. `parse` reads a
key expression's extended key through `key_expression.py`'s own call to
`BIP32KeyData.b58decode`, and a `wsh(...)` or `tr(...)` script through
`miniscript.parse`, so a corpus of real descriptors drives both readers
too; each also has its own direct entry point in the Hypothesis property
suite, `tests/fuzz_test.py`.

**A descriptor is text, so the octets are decoded here and the decode is
total.** `errors="replace"` is what makes it so: no input is filtered out
before `parse` sees it, and octets that are not utf-8 arrive as the
replacement character, which is outside BIP380's INPUT_CHARSET and
refused as any other character outside it would be. A decode that could
raise would make the harness answer for the decoder rather than for the
parser.

A crash on hostile text is a defect in `parse` or in the printer, never in
this harness: nothing validates or normalizes between the decode and the
call. `BTClibException` and `BTClibEccException` are what `parse`
answers a character outside the charset, an unknown function, a bad key
and a checksum that does not match with, so that family is caught below
as the expected outcome. An `IndexError`, a `RecursionError` or an
uncaught assertion is not, and propagates to atheris as the finding it
is.

`network` and `prv_keys` are left at their defaults: both are the
caller's own arguments rather than anything the descriptor says.

**What `parse` accepts prints to a normal form: `str(parse(text))`, parsed
again, prints itself.** It can differ from the text. Among other things it
writes public keys for private ones, hex in lowercase, numbers without
leading zeros, no checksum, the sugared fragment names (`pk(K)` for
`c:pk_k(K)`) and every hardened step in the symbol of the key's last
hardened step. The assertion below reads the printed text again: a second
`parse` that refuses it, or prints it differently, is a defect in the
printer or the parser and propagates to atheris as a finding.

The seed corpus: each `bipNNN_*` seed is one of BIP NNN's examples, from
BIP380 to BIP387 and BIP390, with its checksum.
`ms_*` are miniscript fragments inside `wsh()` composed here from keys of
the BIPs' examples, `own_*` a descriptor composed here, and `pk` and
`wpkh` come from `tests/_data/descriptor_checksums.json`. The checksum is
the BIP's own in `bip380_raw`, the file's in `pk` and `wpkh`, and
BIP380's `descsum_create`'s in the rest. A
seed keeps its checksum because a stranger pasting a descriptor does
too, at a cost: a mutation of it almost never reaches past
`strip_checksum`.
`tests/fuzz_corpus_test.py` holds each seed to the round trip above.
"""

from __future__ import annotations

import sys

import atheris
from btclib.exceptions import BTClibException
from btclib_ecc.exceptions import BTClibEccException

from btclib_wallet.descriptors import descriptors

# tests/fuzz_corpus_test.py reads this by ast.literal_eval, never by
# importing the module -- atheris below is CI-only and undeclared in
# pyproject.toml, so the test must not execute this file
ENTRY_POINTS = ("btclib_wallet.descriptors.descriptors:parse",)


def fuzz_target(data: bytes) -> None:
    """Parse `data` as an output descriptor and print it back.

    A `BTClibException` or `BTClibEccException` from parsing `data` ends
    the run; the module docstring says what propagates.
    """
    try:
        parsed = descriptors.parse(data.decode("utf-8", errors="replace"))
    except (BTClibException, BTClibEccException):
        return
    printed = str(parsed)
    reprinted = str(descriptors.parse(printed))
    if reprinted != printed:
        msg = f"{printed!r} parses and prints as {reprinted!r}"
        raise AssertionError(msg)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
