import pytest
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.asymmetric import rsa
from hypothesis import given
from hypothesis.strategies import binary
from nacl import bindings as sodium
from pytest import mark

from paseto import protocol
from tests import vectors


def key(size):
    return binary(min_size=size, max_size=size)


@mark.filterwarnings("ignore:explicitly setting nonce")
class BaseProtocolTest:
    __test__ = False

    @given(binary(), key(size=32), binary())
    def test_local_roundtrip(self, data, key, f):
        assert self.decrypt(self.encrypt(data, key, f), key, f) == (data, f)


class ProtocolV1Test(BaseProtocolTest):
    __test__ = True

    decrypt = staticmethod(protocol.v1_decrypt)
    encrypt = staticmethod(protocol.v1_encrypt)
    _privkey = rsa.generate_private_key(
        65537, 2048, backends.default_backend()
    )
    _pubkey = _privkey.public_key()

    @mark.parametrize(
        "key,nonce,payload,footer,expected_token", vectors.V1_RFC_LOCAL
    )
    def test_local_rfc_vector(
        self, key, nonce, payload, footer, expected_token
    ):
        token = self.encrypt(payload, key, footer, _n=nonce)
        assert token == expected_token
        assert self.decrypt(token, key, footer) == (payload, footer)

    @mark.parametrize(
        "key,footer,token,exctype,excmatch", vectors.V1_DECRYPT_INVALID
    )
    def test_local_decrypt_invalid(
        self, key, footer, token, exctype, excmatch
    ):
        with pytest.raises(exctype, match=excmatch):
            self.decrypt(token, key, footer)

    @given(binary(), binary())
    def test_public_roundtrip(self, data, f):
        assert protocol.v1_verify(
            protocol.v1_sign(data, self._privkey, f), self._pubkey, f
        ) == (data, f)

    @mark.parametrize("sk,pk,payload,footer,kvt", vectors.V1_RFC_PUBLIC)
    def test_public_rfc_vector(self, sk, pk, payload, footer, kvt):
        assert protocol.v1_verify(kvt, pk, footer) == (payload, footer)
        token = protocol.v1_sign(payload, sk, footer)
        assert protocol.v1_verify(token, pk, footer) == (payload, footer)

    @mark.parametrize(
        "pk,footer,token,exctype,excmatch", vectors.V1_VERIFY_INVALID
    )
    def test_public_verify_invalid(self, pk, footer, token, exctype, excmatch):
        with pytest.raises(exctype, match=excmatch):
            protocol.v1_verify(token, pk, footer)


class ProtocolV2Test(BaseProtocolTest):
    __test__ = True

    decrypt = staticmethod(protocol.v2_decrypt)
    encrypt = staticmethod(protocol.v2_encrypt)

    @mark.parametrize(
        "key,nonce,payload,footer,expected_token", vectors.V2_RFC_LOCAL
    )
    def test_local_rfc_vector(
        self, key, nonce, payload, footer, expected_token
    ):
        token = self.encrypt(payload, key, footer, _n=nonce)
        assert token == expected_token
        assert self.decrypt(token, key, footer) == (payload, footer)

    @mark.parametrize(
        "key,footer,token,exctype,excmatch", vectors.V2_DECRYPT_INVALID
    )
    def test_local_decrypt_invalid(
        self, key, footer, token, exctype, excmatch
    ):
        with pytest.raises(exctype, match=excmatch):
            self.decrypt(token, key, footer)

    @given(binary(), key(size=32), binary())
    def test_public_roundtrip(self, data, seed, f):
        pk, sk = sodium.crypto_sign_seed_keypair(seed)
        assert protocol.v2_verify(protocol.v2_sign(data, sk, f), pk, f) == (
            data,
            f,
        )

    @mark.parametrize("sk,pk,payload,footer,kvt", vectors.V2_RFC_PUBLIC)
    def test_public_rfc_vector(self, sk, pk, payload, footer, kvt):
        assert protocol.v2_verify(kvt, pk, footer) == (payload, footer)
        token = protocol.v2_sign(payload, sk, footer)
        assert protocol.v2_verify(token, pk, footer) == (payload, footer)

    @mark.parametrize(
        "pk,footer,token,exctype,excmatch", vectors.V2_VERIFY_INVALID
    )
    def test_public_verify_invalid(self, pk, footer, token, exctype, excmatch):
        with pytest.raises(exctype, match=excmatch):
            protocol.v2_verify(token, pk, footer)
