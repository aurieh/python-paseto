import base64
import warnings
from contextlib import contextmanager

from cryptography import exceptions as cryptexc
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import ciphers, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives.kdf import hkdf
from nacl import bindings as sodium
from nacl import exceptions as naclexc
from nacl import hashlib, utils
from nacl.bindings.utils import sodium_memcmp

from paseto import exceptions as pexc

EMPTY = b""

V1_LOCAL = b"v1.local."
V1_PUBLIC = b"v1.public."
V2_LOCAL = b"v2.local."
V2_PUBLIC = b"v2.public."

EK_INFO = b"paseto-encryption-key"
AK_INFO = b"paseto-auth-key-for-aead"

EXPLICIT_NONCE_W = "explicitly setting nonce"
BAD_SIGNATURE_ERR = "signature was forged or corrupt"
LIKE_OBJECT_ERR = "a {}-like object is required, not '{}'"


@contextmanager
def _translate_exc(from_, to_, msg="", truncate=False):
    try:
        yield
    except from_ as e:
        raise to_(*(msg and (msg,) or e.args)) from (None if truncate else e)


def b64(bs):
    return base64.urlsafe_b64encode(bs).rstrip(b"=")


def unb64(bs):
    return base64.urlsafe_b64decode(bs + b"=" * (-len(bs) % 4))


def le64(n):
    s = b""
    for i in range(0, 8):
        if i == 7:
            n &= 127
        s += bytes([n & 255])
        n = n >> 8
    return s


def pae(pieces):
    count = len(pieces)
    output = le64(count)
    for i in range(0, count):
        output += le64(len(pieces[i]))
        output += pieces[i]
    return output


def _pack_msg(h, pl, f):
    r = h + b64(pl)
    if f:
        r += b"." + b64(f)
    return r


def _unpack_msg(h, m, f):
    if not m.startswith(h):
        raise pexc.ValueError(
            "invalid message header (must be {})".format(h.decode("utf-8"))
        )
    mp = m[len(h) :].split(b".")
    l = len(mp)
    if l == 1:
        (m,) = mp
        fi = b""
    elif l == 2:
        (m, fi) = mp
    else:
        raise pexc.ValueError("invalid message")
    m = unb64(m)
    fi = unb64(fi)
    if f is not None and not sodium_memcmp(fi, f):
        raise pexc.ValueError("invalid (mismatched) footer")
    return m, fi


def _v1_hmac_sha384(m, k):
    h = hmac.HMAC(k, hashes.SHA384(), backend=backends.default_backend())
    h.update(m)
    return h.finalize()


def v1_get_nonce(m, n):
    return _v1_hmac_sha384(m, n)[:32]


def _v1_derive_key(k, n, info):
    h = hkdf.HKDF(
        algorithm=hashes.SHA384(),
        length=32,
        salt=n[:16],
        info=info,
        backend=backends.default_backend(),
    )
    return h.derive(k)


def _v1_aes_ctr_cipher(k, n):
    return ciphers.Cipher(
        algorithms.AES(k), modes.CTR(n), backend=backends.default_backend()
    )


def v1_encrypt(m, k, f=EMPTY, _n=None):
    h = V1_LOCAL
    if _n is not None:
        warnings.warn(EXPLICIT_NONCE_W, pexc.SecurityWarning)
        n = v1_get_nonce(m, _n)
    else:
        n = v1_get_nonce(m, utils.random(32))  # ?
    ek = _v1_derive_key(k, n, EK_INFO)
    ak = _v1_derive_key(k, n, AK_INFO)
    enc = _v1_aes_ctr_cipher(ek, n[-16:]).encryptor()
    c = enc.update(m) + enc.finalize()
    pre_auth = pae([h, n, c, f])
    t = _v1_hmac_sha384(pre_auth, ak)
    return _pack_msg(h, n + c + t, f)


def v1_decrypt(m, k, f=None):
    h = V1_LOCAL
    m, fi = _unpack_msg(h, m, f)
    n = m[:32]  # ?
    t = m[-48:]  # ?
    c = m[32:-48]
    ek = _v1_derive_key(k, n, EK_INFO)
    ak = _v1_derive_key(k, n, AK_INFO)
    pre_auth = pae([h, n, c, fi])
    t2 = _v1_hmac_sha384(pre_auth, ak)
    if not sodium_memcmp(t, t2):
        raise pexc.InvalidKeyError("mismatching token signature (t != t2)")
    dec = _v1_aes_ctr_cipher(ek, n[-16:]).decryptor()
    return dec.update(c) + dec.finalize(), fi


def _v1_rsa_pss_sha384_opts():
    return dict(
        padding=padding.PSS(
            mgf=padding.MGF1(hashes.SHA384()),
            salt_length=hashes.SHA384.digest_size,
        ),
        algorithm=hashes.SHA384(),
    )


def v1_sign(m, sk, f=EMPTY):
    if not callable(getattr(sk, "sign", None)):  # pragma: no cover
        raise TypeError(LIKE_OBJECT_ERR.format("RSAPrivateKey", type(sk)))
    h = V1_PUBLIC
    m2 = pae([h, m, f])
    sig = sk.sign(m2, **_v1_rsa_pss_sha384_opts())
    return _pack_msg(h, m + sig, f)


def v1_verify(sm, pk, f=None):
    if not callable(getattr(pk, "verify", None)):  # pragma: no cover
        raise TypeError(LIKE_OBJECT_ERR.format("RSAPublicKey", type(pk)))
    h = V1_PUBLIC
    sm, fi = _unpack_msg(h, sm, f)
    s = sm[-256:]
    m = sm[:-256]
    m2 = pae([h, m, fi])
    with _translate_exc(
        cryptexc.InvalidSignature,
        pexc.BadSignatureError,
        msg=BAD_SIGNATURE_ERR,
        truncate=True,
    ):
        pk.verify(s, m2, **_v1_rsa_pss_sha384_opts())
    return m, fi


def v2_encrypt(m, k, f=EMPTY, _n=None):
    h = V2_LOCAL
    if _n is not None:
        warnings.warn(EXPLICIT_NONCE_W, pexc.SecurityWarning)
        nk = _n
    else:
        nk = utils.random(24)
    n = hashlib.blake2b(m, digest_size=24, key=nk).digest()
    pre_auth = pae([h, n, f])
    c = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        message=m, aad=pre_auth, nonce=n, key=k
    )
    return _pack_msg(h, n + c, f)


def v2_decrypt(m, k, f=None):
    h = V2_LOCAL
    m, fi = _unpack_msg(h, m, f)
    nlen = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
    n = m[:nlen]
    c = m[nlen:]
    pre_auth = pae([h, n, fi])
    with _translate_exc(naclexc.CryptoError, pexc.InvalidKeyError):
        p = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext=c, aad=pre_auth, nonce=n, key=k,
        )
    return p, fi


def v2_sign(m, sk, f=EMPTY):
    h = V2_PUBLIC
    m2 = pae([h, m, f])
    sig = sodium.crypto_sign(m2, sk)[: sodium.crypto_sign_BYTES]
    return _pack_msg(h, m + sig, f)


def v2_verify(sm, pk, f=None):
    h = V2_PUBLIC
    sm, fi = _unpack_msg(h, sm, f)
    siglen = sodium.crypto_sign_BYTES
    m = sm[:-siglen]
    s = sm[-siglen:]
    m2 = pae([h, m, fi])
    with _translate_exc(
        naclexc.BadSignatureError,
        pexc.BadSignatureError,
        msg=BAD_SIGNATURE_ERR,
        truncate=True,
    ):
        sodium.crypto_sign_open(s + m2, pk)
    return m, fi
