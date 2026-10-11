# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The btclib fetcher backed by an Electrum server.

`btclib.electrum` is the codec -- the JSON-RPC framing, the shapes of the
methods this fetcher asks, and the merkle-branch check -- and holds
no socket; this module is the `Fetcher` over it, taking a `transport` and
turning each question into a request line and a line back into a btclib
type, the way `EsploraFetcher` and `BitcoinCoreRestFetcher` do over their
own transports.

**`transport` is required, keyword-only, and has no default.**
`LineTransport` (`btclib_wallet.fetch.transport`) carries no host, so a
transport that reaches a server is one constructed with that server's
host -- `TlsLineTransport(host, port)` is the one shipped -- and a default
transport would be a default server, which the next paragraph refuses.

**No `base_url` and no default server.** Unlike `EsploraFetcher`, which
takes a required url with no default, this fetcher takes none at all:
`transport` is the whole of how it reaches a server, and which server
that is is `transport`'s own business. `EsploraFetcher.base_url`'s
reasoning -- `BLOCKSTREAM_INFO` is offered as a value to pass and never
as a default, because which host sees every address a caller looks up is
not btclib's decision to make on anyone's behalf -- applies here with
even less room. Electrum's own shipped server list carries each host's
ports, its pruning and the protocol version it speaks, and nothing about
the certificate it presents, so which of its entries a transport
verifying against a public CA store reaches is not a question the list
answers. Electrum's own client does not ask it either: where the
CA-signed handshake fails it pins the certificate that server presented
and connects with `check_hostname` off (`electrum/interface.py`,
`Interface._get_ssl_context`), so being listed says what protocol
version a server speaks and not that its certificate is one a strict
transport accepts. Entries share registrable domains, so the list names
fewer operators than hosts, and a caller running their own server is
invisible to it entirely. Naming any one entry as a constant would
repeat the mistake `BLOCKSTREAM_INFO` already refuses.

**A question the interface does not declare, answered by nothing else in
this package.** `get_tx_merkle`, `verify_tx` and `get_block_headers` are
not on `Fetcher`:
adding a return type no other backend can honor is what the interface's
abstract methods, each with a return type of its own, already exist to
avoid, and both the issue and issue btclib-org/btclib#1193 hold the interface
itself unchanged. What `Fetcher`'s own class docstring calls "evidence beside
the data" is what these two are -- a merkle branch checked against a header this
fetcher fetched on its own, which is a different kind of answer from the other
backends' word for it, and the reason this backend exists.
"""

from __future__ import annotations

from typing import cast

from btclib import electrum
from btclib.alias import Octets
from btclib.block.block_header import BlockHeader
from btclib.exceptions import BTClibTypeError, BTClibValueError, FetchError
from btclib.fee import FeeRate
from btclib.network import NETWORKS
from btclib.tx import Tx
from btclib.utils import bytes_from_octets, is_integer
from typing_extensions import override

from btclib_wallet.fetch.fee_estimator import FeeQuote, valid_confirmation_target
from btclib_wallet.fetch.fetcher import (
    NetworkVerifyingFetcher,
    block_header_from_raw,
    block_header_height,
    client_errors,
    fetch_errors,
    tx_from_raw,
    tx_id_hex,
)
from btclib_wallet.fetch.transport import DEFAULT_TIMEOUT, LineTransport, valid_timeout

__all__ = [
    "ElectrumFetcher",
]


class ElectrumFetcher(NetworkVerifyingFetcher):
    """Every `Fetcher` question, and a merkle branch, from an Electrum server.

    `get_tx` is `blockchain.transaction.get`, the raw hex decoded and
    handed to `tx_from_raw`, which recomputes the id the same way every
    other backend does. `get_block_count` and `get_best_block_id` are
    both `blockchain.headers.subscribe`, asked once each: the protocol
    answers the tip's height together with its header rather than a
    separate hash field, so the id `get_best_block_id` returns is not the
    server's word -- it is `BlockHeader.hash` of the header
    `block_header_from_raw` has already checked is well-formed and within
    the network's proof-of-work limit, the same check `get_block_header` runs.
    `get_block_header` is `blockchain.block.header`, `cp_height` left
    unsent.

    `get_block_headers` is `blockchain.block.headers`: up to a server's
    own maximum of consecutive headers in one answer, each checked as
    `get_block_header` checks one, and each chained to the one before it.

    `get_tx_merkle` is `blockchain.transaction.get_merkle`, returning the
    branch and position `btclib.electrum.MerkleProof` carries.
    `verify_tx` fetches the header at the height asked for with
    `get_block_header` -- the caller's own height, not the proof's
    unchecked `block_height` -- and checks the branch against it with
    `btclib.electrum.verify_merkle_proof`, answering `False` for a
    malformed branch or a wrong position the way
    `btclib.block.merkle_proof.verify` does, and still raising for
    anything `get_block_header` itself refuses.

    Also a `FeeEstimator`: `estimate_fee` is `blockchain.estimatefee`,
    answered for the target asked -- the protocol carries no field
    equivalent to Core's `blocks`, so unlike the other two backends this
    one cannot report a clamp the server may have applied underneath it.

    `get_tx_out` is not overridden, and stays the `Fetcher` base's
    derivation from `get_tx`. The protocol answers a script hash's
    history and its unspent outputs, `blockchain.scripthash.get_history`
    and `.listunspent`, but `ElectrumFetcher` does not ask either
    question: every `Fetcher` question is keyed on an identifier the
    caller already holds -- a txid, a height, nothing -- and a script is
    not one.
    """

    def __init__(
        self,
        network: str = "mainnet",
        *,
        transport: LineTransport,
        verify_network: bool = True,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        super().__init__(network, verify_network=verify_network)
        if not callable(transport):
            raise BTClibTypeError(f"not a callable transport: {transport!r}")
        self.transport = transport
        # checked here for a transport of the caller's that checks nothing
        self.timeout = valid_timeout(timeout)
        self._next_id = 0

    def _next_request_id(self) -> int:
        """Return a fresh request id, one higher than the last.

        A counter and not a constant: `decode_response` refuses a reply
        that answers a different id, so two requests sharing one id could
        not be told apart by anything this codec checks.
        """
        self._next_id += 1
        return self._next_id

    def _round_trip(self, request: bytes) -> bytes:
        """Send one request line and return the line answering it.

        The one call site that reaches `self.transport`, so a translation
        of what it raises is written once. `LineTransport`'s own
        docstring is where the exception contract this wraps is stated.
        """
        with client_errors():
            return self.transport(request, self.timeout)

    def _tip(self) -> electrum.HeaderTip:
        """Return the chain tip `blockchain.headers.subscribe` answers."""
        request_id = self._next_request_id()
        line = self._round_trip(electrum.headers_subscribe_request(request_id))
        with fetch_errors("headers.subscribe"):
            return electrum.headers_subscribe_response(line, request_id)

    def _header_at(self, height: int) -> BlockHeader:
        """Return the header at this height, checked, asking nothing else.

        The seam `get_block_header` and `assert_network` share, the way
        `_tip` is the one `get_block_count` and `get_best_block_id`
        share: `assert_network` reaches the genesis header through this
        and not through `get_block_header`, which calls `_verify_once`.

        `block_header_from_raw` is what checks the eighty bytes, so the
        header a caller compares or hashes is one that is well-formed and
        within the network's proof-of-work limit, and not the server's word
        for either.
        """
        request_id = self._next_request_id()
        line = self._round_trip(electrum.block_header_request(request_id, height))
        with fetch_errors(f"block header {height}"):
            raw = electrum.block_header_response(line, request_id)
        return block_header_from_raw(raw, height, network=self.network)

    @override
    def get_tx(self, tx_id: Octets) -> Tx:
        """Return the transaction with this id, via `transaction.get`."""
        self._verify_once()
        hex_ = tx_id_hex(tx_id)
        request_id = self._next_request_id()
        line = self._round_trip(electrum.transaction_get_request(request_id, hex_))
        with fetch_errors(f"transaction {hex_}"):
            raw = electrum.transaction_get_response(line, request_id)
        return tx_from_raw(raw, hex_, self.network)

    @override
    def get_block_count(self) -> int:
        """Return the height of the chain tip, via `headers.subscribe`."""
        self._verify_once()
        return self._tip().height

    @override
    def get_best_block_id(self) -> bytes:
        """Return the id of the chain tip, recomputed from its own header.

        `headers.subscribe` answers the header itself rather than a
        separate hash field, so this is not the server's word: it is
        `block_header_from_raw`'s check on the bytes it sent, and then
        the hash of the header that passed it.
        """
        self._verify_once()
        tip = self._tip()
        header = block_header_from_raw(tip.header, tip.height, network=self.network)
        return header.hash

    @override
    def get_block_header(self, height: int) -> BlockHeader:
        """Return the header at this height, via `blockchain.block.header`."""
        self._verify_once()
        return self._header_at(block_header_height(height))

    def get_block_headers(self, start_height: int, count: int) -> list[BlockHeader]:
        """Return up to `count` consecutive headers from `start_height`.

        `blockchain.block.headers`, read in the answer shape of protocol
        1.5 and earlier: one object with `count`, `hex` and `max`. From 1.6
        the headers come as a list, which this does not read. A server may
        answer fewer than asked, by its own maximum or by reaching its tip,
        so the list can be shorter than `count`, or empty. What is
        refused: more headers than asked for, a `hex` that is not eighty
        bytes for each header the answer counts, any header
        `block_header_from_raw` refuses, and a header whose
        `previous_block_hash` is not the hash of the one before it. The
        first header's parent is not checked: the chunk carries no header
        below it.
        """
        self._verify_once()
        start_height = block_header_height(start_height)
        if not is_integer(count):
            raise BTClibTypeError(f"invalid count type: {type(count).__name__}")
        if count < 1:
            raise BTClibValueError(f"invalid count: {count}")
        request_id = self._next_request_id()
        request = electrum.encode_request(
            request_id, "blockchain.block.headers", [start_height, count]
        )
        line = self._round_trip(request)
        source = f"block headers {start_height}+{count}"
        with fetch_errors(source):
            result = electrum.decode_response(line, request_id)
            if not isinstance(result, dict):
                raise BTClibTypeError(f"not an object: {result!r}")
            claimed = result.get("count")
            if not is_integer(claimed) or not 0 <= cast(int, claimed) <= count:
                raise BTClibValueError(f"invalid count: {claimed!r}")
            answered = cast(int, claimed)
            hex_ = result.get("hex")
            if not isinstance(hex_, str):
                raise BTClibTypeError(f"not a hex string: {hex_!r}")
            raw = bytes_from_octets(hex_)
            if len(raw) != answered * 80:
                err_msg = f"{len(raw)} bytes are not {answered} headers"
                raise BTClibValueError(err_msg)
        headers = [
            block_header_from_raw(
                raw[i * 80 : (i + 1) * 80], start_height + i, network=self.network
            )
            for i in range(answered)
        ]
        for i in range(1, answered):
            if headers[i].previous_block_hash != headers[i - 1].hash:
                err_msg = f"{source}: header {start_height + i} does not follow"
                err_msg += f" header {start_height + i - 1}"
                raise FetchError(err_msg)
        return headers

    @override
    def assert_network(self) -> None:
        """Raise unless the server serves the chain this fetcher labels with.

        One request and one comparison: `blockchain.block.header` at
        height 0 -- the same method `get_block_header` asks for every
        other height, asked here for the block every chain starts from --
        against `NETWORKS[self.network].genesis_block`. What is compared
        is `BlockHeader.hash` of the eighty bytes `_header_at` has
        checked, so this backend answers the question the way it answers
        `get_best_block_id`: by hashing a header rather than by reading a
        hash the server chose. `server.features` carries a `genesis_hash`
        member and is what Electrum's own client compares
        (`electrum/interface.py`); the header is asked for instead
        because it makes the server produce eighty bytes that hash to the
        genesis rather than repeat a string, and because it needs no
        codec function `btclib.electrum` does not already have.

        Worth the call, because the failure it catches is silent, the
        same one `BitcoinCoreFetcher.assert_network`'s docstring names: a
        fetcher labelled `mainnet` over a server on another chain renders
        a mainnet address for every output it fetches, for coins that are
        not there. It is sharper here than elsewhere, because `verify_tx`
        checks a branch against a header fetched from that same server:
        a caller on the wrong chain is otherwise handed a proof that is
        valid and about a chain they did not mean.

        What a genesis hash cannot separate is two signets, and
        `EsploraFetcher.assert_network`'s docstring is where that is
        written down. This class takes no `signet_challenge` of its own,
        for the reason that class takes none: nothing among the methods
        `btclib.electrum` speaks is a signet's challenge to compare
        against.
        """
        reported = self._header_at(0).hash
        expected = NETWORKS[self.network].genesis_block
        if reported != expected:
            err_msg = "the server serves a chain whose genesis is"
            err_msg += f" {reported.hex()}, not the {expected.hex()}"
            err_msg += f" this {self.network} fetcher was built for"
            raise BTClibValueError(err_msg)

    def get_tx_merkle(self, tx_id: Octets, height: int) -> electrum.MerkleProof:
        """Return the branch proving `tx_id` confirmed at `height`.

        `blockchain.transaction.get_merkle`, the one question no other
        backend here can answer at all.
        """
        self._verify_once()
        hex_ = tx_id_hex(tx_id)
        height = block_header_height(height)
        request_id = self._next_request_id()
        line = self._round_trip(
            electrum.transaction_get_merkle_request(request_id, hex_, height)
        )
        with fetch_errors(f"transaction {hex_} merkle"):
            return electrum.transaction_get_merkle_response(line, request_id)

    def verify_tx(self, tx_id: Octets, height: int) -> bool:
        """Return whether `tx_id` is proven confirmed at `height`.

        Fetches the header at `height` and the branch separately, then
        checks the second against the first's merkle root -- see this
        class's own docstring for what each half already checks on its
        own.
        """
        header = self.get_block_header(height)
        proof = self.get_tx_merkle(tx_id, height)
        return electrum.verify_merkle_proof(tx_id, proof, header)

    def estimate_fee(self, target: int) -> FeeQuote:
        """Return a fee rate expected to confirm within `target` blocks.

        `blockchain.estimatefee`. `-1`, the protocol's own way of saying
        no estimate is available, is a decline and raised as a
        `FetchError` rather than reaching `FeeRate` -- no sentinel
        reaches the return type, the way `Broadcaster`'s third contract
        bullet already requires of a refusal. Servers commonly proxy this
        answer from a node's own `estimatesmartfee`, so it is read in the
        same BTC/kvB unit `FeeRate.from_btc_per_kvbyte` already converts.
        """
        self._verify_once()
        target = valid_confirmation_target(target)
        request_id = self._next_request_id()
        line = self._round_trip(electrum.estimate_fee_request(request_id, target))
        with fetch_errors("blockchain.estimatefee"):
            result = electrum.estimate_fee_response(line, request_id)
            if result == -1:
                err_msg = f"blockchain.estimatefee: no estimate for target {target}"
                raise FetchError(err_msg)
            rate = FeeRate.from_btc_per_kvbyte(result, round_up=True)
            return FeeQuote(rate=rate, target=target)
