import base64

from cryptography.hazmat import backends
from cryptography.hazmat.primitives import serialization

from paseto import exceptions


def unhex(s):
    return base64.b16decode("".join(s.split()), casefold=True)


EMPTY = b""

V1_NULL_NONCE = b"\x00" * 32

V1_RFC_LOCAL_KEY = unhex(
    """
70717273 74757677 78797a7b 7c7d7e7f
80818283 84858687 88898a8b 8c8d8e8f
"""
)
V1_RFC_NONCE = unhex(
    """
26f75533 54482a1d 91d47846 27854b8d
a6b8042a 7966523c 2b404e8d bbe7f7f2
"""
)

# Test vectors taken from:
# https://paseto.io/rfc/draft-00
# A.1.1.
V1_RFC_LOCAL = [
    (
        # v1-E-1
        V1_RFC_LOCAL_KEY,
        V1_NULL_NONCE,
        b'{"data":"this is a signed message","exp":"2019-01-01T00:00:00+00:00"}',
        EMPTY,
        b"v1.local.WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8",
    ),
    (
        # v1-E-2
        V1_RFC_LOCAL_KEY,
        V1_NULL_NONCE,
        b'{"data":"this is a secret message","exp":"2019-01-01T00:00:00+00:00"}',
        EMPTY,
        b"v1.local.w_NOpjgte4bX-2i1JAiTQzHoGUVOgc2yqKqsnYGmaPaCu_KWUkRGlCRnOvZZxeH4HTykY7AE_jkzSXAYBkQ1QnwvKS16uTXNfnmp8IRknY76I2m3S5qsM8klxWQQKFDuQHl8xXV0MwAoeFh9X6vbwIqrLlof3s4PMjRDwKsxYzkMr1RvfDI8emoPoW83q4Q60_xpHaw",
    ),
    (
        # v1-E-3
        V1_RFC_LOCAL_KEY,
        V1_RFC_NONCE,
        b'{"data":"this is a signed message","exp":"2019-01-01T00:00:00+00:00"}',
        EMPTY,
        b"v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3syBYyjKIOeWnsFQB6Yef-1ov9rvqt7TmwONUHeJUYk4IK_JEdUeo_uFRqAIgHsiGCg",
    ),
    (
        # v1-E-4
        V1_RFC_LOCAL_KEY,
        V1_RFC_NONCE,
        b'{"data":"this is a secret message","exp":"2019-01-01T00:00:00+00:00"}',
        EMPTY,
        b"v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbbpOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEqGNeeWXOyWWHoJQIe0d5nTdvejdt2Srz_5Q0QG4oiz1gB_wmv4U5pifedaZbHXUTWXchFEi0etJ4u6tqgxZSklcec",
    ),
    (
        # v1-E-5
        V1_RFC_LOCAL_KEY,
        V1_RFC_NONCE,
        b'{"data":"this is a signed message","exp":"2019-01-01T00:00:00+00:00"}',
        b'{"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}',
        b"v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3szA28OabR192eRqiyspQ6xPM35NMR-04-FhRJZEWiF0W5oWjPVtGPjeVjm2DI4YtJg.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9",
    ),
    (
        # v1-E-6
        V1_RFC_LOCAL_KEY,
        V1_RFC_NONCE,
        b'{"data":"this is a secret message","exp":"2019-01-01T00:00:00+00:00"}',
        b'{"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}',
        b"v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbbpOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEqGNeeWXOyWWHoJQIe0d5nTdvcT2vnER6NrJ7xIowvFba6J4qMlFhBnYSxHEq9v9NlzcKsz1zscdjcAiXnEuCHyRSc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9",
    ),
]

V1_NULL_KEY = b"\x00" * 32

V1_DECRYPT_INVALID = [
    (
        V1_RFC_LOCAL_KEY,
        EMPTY,
        b"v1.public.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3syBYyjKIOeWnsFQB6Yef-1ov9rvqt7TmwONUHeJUYk4IK_JEdUeo_uFRqAIgHsiGCg",
        exceptions.ValueError,
        r"invalid message header \(must be v1\.local\.\)",
    ),
    (
        V1_RFC_LOCAL_KEY,
        EMPTY,
        b"v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3szA28OabR192eRqiyspQ6xPM35NMR-04-FhRJZEWiF0W5oWjPVtGPjeVjm2DI4YtJg.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9.Zm9v",
        exceptions.ValueError,
        r"invalid message",
    ),
    (
        V1_RFC_LOCAL_KEY,
        b"bar",
        b"v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3szA28OabR192eRqiyspQ6xPM35NMR-04-FhRJZEWiF0W5oWjPVtGPjeVjm2DI4YtJg.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9",
        exceptions.ValueError,
        r"invalid \(mismatched\) footer",
    ),
    (
        V1_NULL_KEY,
        None,
        b"v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3szA28OabR192eRqiyspQ6xPM35NMR-04-FhRJZEWiF0W5oWjPVtGPjeVjm2DI4YtJg.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9",
        exceptions.InvalidKeyError,
        r"mismatching token signature",
    ),
]

V1_RFC_PUBLIC_PRIVATE_KEY = serialization.load_pem_private_key(
    b"""-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAyaTgTt53ph3p5GHgwoGWwz5hRfWXSQA08NCOwe0FEgALWos9
GCjNFCd723nCHxBtN1qd74MSh/uN88JPIbwxKheDp4kxo4YMN5trPaF0e9G6Bj1N
02HnanxFLW+gmLbgYO/SZYfWF/M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJ
AZTU5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5IpNx
kRnAwIMjeTJB/0AIELh0mE5vwdihOCbdV6alUyhKC1+1w/FW6HWcp/JG1kKC8DPI
idZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8owIDAQABAoIBAF22jLDa34yKdns3
qfd7to+C3D5hRzAcMn6Azvf9qc+VybEI6RnjTHxDZWK5EajSP4/sQ15e8ivUk0Jo
WdJ53feL+hnQvwsab28gghSghrxM2kGwGA1XgO+SVawqJt8SjvE+Q+//01ZKK0Oy
A0cDJjX3L9RoPUN/moMeAPFw0hqkFEhm72GSVCEY1eY+cOXmL3icxnsnlUD//SS9
q33RxF2y5oiW1edqcRqhW/7L1yYMbxHFUcxWh8WUwjn1AAhoCOUzF8ZB+0X/PPh+
1nYoq6xwqL0ZKDwrQ8SDhW/rNDLeO9gic5rl7EetRQRbFvsZ40AdsX2wU+lWFUkB
42AjuoECgYEA5z/CXqDFfZ8MXCPAOeui8y5HNDtu30aR+HOXsBDnRI8huXsGND04
FfmXR7nkghr08fFVDmE4PeKUk810YJb+IAJo8wrOZ0682n6yEMO58omqKin+iIUV
rPXLSLo5CChrqw2J4vgzolzPw3N5I8FJdLomb9FkrV84H+IviPIylyECgYEA3znw
AG29QX6ATEfFpGVOcogorHCntd4niaWCq5ne5sFL+EwLeVc1zD9yj1axcDelICDZ
xCZynU7kDnrQcFkT0bjH/gC8Jk3v7XT9l1UDDqC1b7rm/X5wFIZ/rmNa1rVZhL1o
/tKx5tvM2syJ1q95v7NdygFIEIW+qbIKbc6Wz0MCgYBsUZdQD+qx/xAhELX364I2
epTryHMUrs+tGygQVrqdiJX5dcDgM1TUJkdQV6jLsKjPs4Vt6OgZRMrnuLMsk02R
3M8gGQ25ok4f4nyyEZxGGWnVujn55KzUiYWhGWmhgp18UCkoYa59/Q9ss+gocV9h
B9j9Q43vD80QUjiF4z0DQQKBgC7XQX1VibkMim93QAnXGDcAS0ij+w02qKVBjcHk
b9mMBhz8GAxGOIu7ZJafYmxhwMyVGB0I1FQeEczYCJUKnBYN6Clsjg6bnBT/z5bJ
x/Jx1qCzX3Uh6vLjpjc5sf4L39Tyye1u2NXQmZPwB5x9BdcsFConSq/s4K1LJtUT
3KFxAoGBANGcQ8nObi3m4wROyKrkCWcWxFFMnpwxv0pW727Hn9wuaOs4UbesCnwm
pcMTfzGUDuzYXCtAq2pJl64HG6wsdkWmjBTJEpm6b9ibOBN3qFV2zQ0HyyKlMWxI
uVSj9gOo61hF7UH9XB6R4HRdlpBOuIbgAWZ46dkj9/HM9ovdP0Iy
-----END RSA PRIVATE KEY-----""",
    password=None,
    backend=backends.default_backend(),
)
V1_RFC_PUBLIC_PUBLIC_KEY = serialization.load_pem_public_key(
    b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyaTgTt53ph3p
5GHgwoGWwz5hRfWXSQA08NCOwe0FEgALWos9GCjNFCd723nCHxBtN1qd
74MSh/uN88JPIbwxKheDp4kxo4YMN5trPaF0e9G6Bj1N02HnanxFLW+g
mLbgYO/SZYfWF/M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJAZTU
5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5
IpNxkRnAwIMjeTJB/0AIELh0mE5vwdihOCbdV6alUyhKC1+1w/FW6HWc
p/JG1kKC8DPIidZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8owIDAQAB
-----END PUBLIC KEY-----""",
    backend=backends.default_backend(),
)

# Test vectors taken from:
# https://paseto.io/rfc/draft-00
# A.1.2.
V1_RFC_PUBLIC = [
    # XXX: Official test vectors specify invalid payloads.
    (
        # v1-S-1
        V1_RFC_PUBLIC_PRIVATE_KEY,
        V1_RFC_PUBLIC_PUBLIC_KEY,
        b'{"data":"this is a signed message","exp":"2019-01-01T00:00:00+00:00"}',
        EMPTY,
        b"v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9cIZKahKeGM5kiAS_4D70Qbz9FIThZpxetJ6n6E6kXP_119SvQcnfCSfY_gG3D0Q2v7FEtm2Cmj04lE6YdgiZ0RwA41WuOjXq7zSnmmHK9xOSH6_2yVgt207h1_LphJzVztmZzq05xxhZsV3nFPm2cCu8oPceWy-DBKjALuMZt_Xj6hWFFie96SfQ6i85lOsTX8Kc6SQaG-3CgThrJJ6W9DC-YfQ3lZ4TJUoY3QNYdtEgAvp1QuWWK6xmIb8BwvkBPej5t88QUb7NcvZ15VyNw3qemQGn2ITSdpdDgwMtpflZOeYdtuxQr1DSGO2aQyZl7s0WYn1IjdQFx6VjSQ4yfw",
    ),
    (
        # v1-S-2
        V1_RFC_PUBLIC_PRIVATE_KEY,
        V1_RFC_PUBLIC_PUBLIC_KEY,
        b'{"data":"this is a signed message","exp":"2019-01-01T00:00:00+00:00"}',
        b'{"kid":"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn"}',
        b"v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9sBTIb0J_4misAuYc4-6P5iR1rQighzktpXhJ8gtrrp2MqSSDkbb8q5WZh3FhUYuW_rg2X8aflDlTWKAqJkM3otjYwtmfwfOhRyykxRL2AfmIika_A-_MaLp9F0iw4S1JetQQDV8GUHjosd87TZ20lT2JQLhxKjBNJSwWue8ucGhTgJcpOhXcthqaz7a2yudGyd0layzeWziBhdQpoBR6ryTdtIQX54hP59k3XCIxuYbB9qJMpixiPAEKBcjHT74sA-uukug9VgKO7heWHwJL4Rl9ad21xyNwaxAnwAJ7C0fN5oGv8Rl0dF11b3tRmsmbDoIokIM0Dba29x_T3YzOyg.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9",
    ),
]

V1_PUBLIC_PUBLIC_KEY2 = serialization.load_pem_public_key(
    b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1ymoKthVYX/wcybdyxvV
PqTt4a4Ih0sYOUglkvjEHExMKK2c4gVPWxgfljTGg8as/GPvtYLus42hhacaTQyD
9z4qBYxrSZO84ATOeE06peoFwM98C7/ONaLhxP4b7riMvLTXedvTbUqZeBdUrt+K
zbTKLlyZtlHdOTOOqBJkJE6PZNejJW9DNJfP+Qa1MdF98qrYOb91MJ2rrWlrMPgs
6uLWBjjX5l1Ax+6oA4Gg2iWjxvZzcwj1jSXtGLCYnsBbS3XnjfET5obLuFgZGosh
f0dqv0TUtM3RfMYwfGjb5hRUr9T9MBJfkQ/eFrX1ZK1L6VEaGKilPqDgJyjO4wxv
swIDAQAB
-----END PUBLIC KEY-----""",
    backend=backends.default_backend(),
)

V1_VERIFY_INVALID = [
    (
        V1_RFC_PUBLIC_PUBLIC_KEY,
        EMPTY,
        b"v1.local.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9sBTIb0J_4misAuYc4-6P5iR1rQighzktpXhJ8gtrrp2MqSSDkbb8q5WZh3FhUYuW_rg2X8aflDlTWKAqJkM3otjYwtmfwfOhRyykxRL2AfmIika_A-_MaLp9F0iw4S1JetQQDV8GUHjosd87TZ20lT2JQLhxKjBNJSwWue8ucGhTgJcpOhXcthqaz7a2yudGyd0layzeWziBhdQpoBR6ryTdtIQX54hP59k3XCIxuYbB9qJMpixiPAEKBcjHT74sA-uukug9VgKO7heWHwJL4Rl9ad21xyNwaxAnwAJ7C0fN5oGv8Rl0dF11b3tRmsmbDoIokIM0Dba29x_T3YzOyg.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9",
        exceptions.ValueError,
        r"invalid message header \(must be v1\.public\.\)",
    ),
    (
        V1_RFC_PUBLIC_PUBLIC_KEY,
        EMPTY,
        b"v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9sBTIb0J_4misAuYc4-6P5iR1rQighzktpXhJ8gtrrp2MqSSDkbb8q5WZh3FhUYuW_rg2X8aflDlTWKAqJkM3otjYwtmfwfOhRyykxRL2AfmIika_A-_MaLp9F0iw4S1JetQQDV8GUHjosd87TZ20lT2JQLhxKjBNJSwWue8ucGhTgJcpOhXcthqaz7a2yudGyd0layzeWziBhdQpoBR6ryTdtIQX54hP59k3XCIxuYbB9qJMpixiPAEKBcjHT74sA-uukug9VgKO7heWHwJL4Rl9ad21xyNwaxAnwAJ7C0fN5oGv8Rl0dF11b3tRmsmbDoIokIM0Dba29x_T3YzOyg.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9.Zm9v",
        exceptions.ValueError,
        r"invalid message",
    ),
    (
        V1_RFC_PUBLIC_PUBLIC_KEY,
        b"foo",
        b"v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9sBTIb0J_4misAuYc4-6P5iR1rQighzktpXhJ8gtrrp2MqSSDkbb8q5WZh3FhUYuW_rg2X8aflDlTWKAqJkM3otjYwtmfwfOhRyykxRL2AfmIika_A-_MaLp9F0iw4S1JetQQDV8GUHjosd87TZ20lT2JQLhxKjBNJSwWue8ucGhTgJcpOhXcthqaz7a2yudGyd0layzeWziBhdQpoBR6ryTdtIQX54hP59k3XCIxuYbB9qJMpixiPAEKBcjHT74sA-uukug9VgKO7heWHwJL4Rl9ad21xyNwaxAnwAJ7C0fN5oGv8Rl0dF11b3tRmsmbDoIokIM0Dba29x_T3YzOyg.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9",
        exceptions.ValueError,
        r"invalid \(mismatched\) footer",
    ),
    (
        V1_PUBLIC_PUBLIC_KEY2,
        None,
        b"v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9sBTIb0J_4misAuYc4-6P5iR1rQighzktpXhJ8gtrrp2MqSSDkbb8q5WZh3FhUYuW_rg2X8aflDlTWKAqJkM3otjYwtmfwfOhRyykxRL2AfmIika_A-_MaLp9F0iw4S1JetQQDV8GUHjosd87TZ20lT2JQLhxKjBNJSwWue8ucGhTgJcpOhXcthqaz7a2yudGyd0layzeWziBhdQpoBR6ryTdtIQX54hP59k3XCIxuYbB9qJMpixiPAEKBcjHT74sA-uukug9VgKO7heWHwJL4Rl9ad21xyNwaxAnwAJ7C0fN5oGv8Rl0dF11b3tRmsmbDoIokIM0Dba29x_T3YzOyg.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9",
        exceptions.BadSignatureError,
        r"signature was forged or corrupt",
    ),
]


V2_NULL_NONCE = b"\x00" * 24

V2_RFC_LOCAL_KEY = unhex(
    """
70717273 74757677 78797a7b 7c7d7e7f
80818283 84858687 88898a8b 8c8d8e8f
"""
)
V2_RFC_NONCE = unhex(
    """
45742c97 6d684ff8 4ebdc0de 59809a97
cda2f64c 84fda19b
"""
)

# Test vectors taken from:
# https://paseto.io/rfc/draft-00
# A.2.1.
V2_RFC_LOCAL = [
    (
        # v2-E-1
        V2_RFC_LOCAL_KEY,
        V2_NULL_NONCE,
        b'{"data":"this is a signed message","exp":"2019-01-01T00:00:00+00:00"}',
        EMPTY,
        b"v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4PnW8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVODyfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ",
    ),
    (
        # v2-E-2
        V2_RFC_LOCAL_KEY,
        V2_NULL_NONCE,
        b'{"data":"this is a secret message","exp":"2019-01-01T00:00:00+00:00"}',
        EMPTY,
        b"v2.local.CH50H-HM5tzdK4kOmQ8KbIvrzJfjYUGuu5Vy9ARSFHy9owVDMYg3-8rwtJZQjN9ABHb2njzFkvpr5cOYuRyt7CRXnHt42L5yZ7siD-4l-FoNsC7J2OlvLlIwlG06mzQVunrFNb7Z3_CHM0PK5w",
    ),
    (
        # v2-E-3
        V2_RFC_LOCAL_KEY,
        V2_RFC_NONCE,
        b'{"data":"this is a signed message","exp":"2019-01-01T00:00:00+00:00"}',
        EMPTY,
        b"v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-O5xRBN076fSDPo5xUCPpBA",
    ),
    (
        # v2-E-4
        V2_RFC_LOCAL_KEY,
        V2_RFC_NONCE,
        b'{"data":"this is a secret message","exp":"2019-01-01T00:00:00+00:00"}',
        EMPTY,
        b"v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DPbIxtjGvNRAwsLK7LcV8oQ",
    ),
    # XXX: strangely, the official test vectors specify invalid
    # footers for vectors v2-E-5 and v2-E-6. Valid footers taken from:
    # https://github.com/Ianleeclark/Paseto/blob/624327cc7814c469143a245c2d2ee52c94a497e0/test/fixtures/test_vectors/v2_local.exs#L34-L51
    (
        # v2-E-5
        V2_RFC_LOCAL_KEY,
        V2_RFC_NONCE,
        b'{"data":"this is a signed message","exp":"2019-01-01T00:00:00+00:00"}',
        b'{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}',
        b"v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
    ),
    (
        # v2-E-6
        V2_RFC_LOCAL_KEY,
        V2_RFC_NONCE,
        b'{"data":"this is a secret message","exp":"2019-01-01T00:00:00+00:00"}',
        b'{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}',
        b"v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
    ),
]

V2_NULL_KEY = b"\x00" * 32

V2_DECRYPT_INVALID = [
    (
        V2_RFC_LOCAL_KEY,
        EMPTY,
        b"v2.public.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
        exceptions.ValueError,
        r"invalid message header \(must be v2\.local\.\)",
    ),
    (
        V2_RFC_LOCAL_KEY,
        EMPTY,
        b"v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9.Zm9v",
        exceptions.ValueError,
        r"invalid message",
    ),
    (
        V2_RFC_LOCAL_KEY,
        b"bar",
        b"v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
        exceptions.ValueError,
        r"invalid \(mismatched\) footer",
    ),
    (
        V2_NULL_KEY,
        None,
        b"v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUrIu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
        exceptions.InvalidKeyError,
        r"",  # TODO
    ),
]

V2_RFC_PUBLIC_PRIVATE_KEY = unhex(
    """
b4cbfb43 df4ce210 727d953e 4a713307
fa19bb7d 9f850414 38d9e11b 942a3774
1eb9dbbb bc047c03 fd70604e 0071f098
7e16b28b 757225c1 1f00415d 0e20b1a2
"""
)
V2_RFC_PUBLIC_PUBLIC_KEY = unhex(
    """
1eb9dbbb bc047c03 fd70604e 0071f098
7e16b28b 757225c1 1f00415d 0e20b1a2
"""
)

# Test vectors taken from:
# https://paseto.io/rfc/draft-00
# A.2.2.
V2_RFC_PUBLIC = [
    (
        # v2-S-1
        V2_RFC_PUBLIC_PRIVATE_KEY,
        V2_RFC_PUBLIC_PUBLIC_KEY,
        b'{"data":"this is a signed message","exp":"2019-01-01T00:00:00+00:00"}',
        EMPTY,
        b"v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9HQr8URrGntTu7Dz9J2IF23d1M7-9lH9xiqdGyJNvzp4angPW5Esc7C5huy_M8I8_DjJK2ZXC2SUYuOFM-Q_5Cw",
    ),
    (
        # v2-S-2
        V2_RFC_PUBLIC_PRIVATE_KEY,
        V2_RFC_PUBLIC_PUBLIC_KEY,
        b'{"data":"this is a signed message","exp":"2019-01-01T00:00:00+00:00"}',
        # XXX: Wrong footer here as well.
        b'{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}',
        b"v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
    ),
]

V2_PUBLIC_PUBLIC_NULL_KEY = b"\x00" * 32

V2_VERIFY_INVALID = [
    (
        V2_RFC_PUBLIC_PUBLIC_KEY,
        EMPTY,
        b"v2.local.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
        exceptions.ValueError,
        r"invalid message header \(must be v2\.public\.\)",
    ),
    (
        V2_RFC_PUBLIC_PUBLIC_KEY,
        EMPTY,
        b"v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9.Zm9v",
        exceptions.ValueError,
        r"invalid message",
    ),
    (
        V2_RFC_PUBLIC_PUBLIC_KEY,
        b"bar",
        b"v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
        exceptions.ValueError,
        r"invalid \(mismatched\) footer",
    ),
    (
        V2_PUBLIC_PUBLIC_NULL_KEY,
        None,
        b"v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
        exceptions.BadSignatureError,
        r"signature was forged or corrupt",
    ),
]
