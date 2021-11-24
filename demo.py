#! /usr/bin/env python3
#
# Provides :
# 1. an implementation of Linkable Spontaneus Anonymous Group Signature
# over elliptic curve cryptography
#
# Implementation of cryptographic scheme from: https://eprint.iacr.org/2004/027.pdf
#
#
# Written in 2017 by Fernanddo Lobato Meeser and placed in the public domain.
# 2.

import os
import hashlib
import functools
import ecdsa
import web3
import eth_keys
from decimal import Decimal

from ecdsa.util import randrange
from ecdsa.ecdsa import curve_secp256k1
from ecdsa.curves import SECP256k1
from ecdsa import numbertheory
from eth_account._utils.signing import (
    extract_chain_id,
    to_standard_v,
    serializable_unsigned_transaction_from_dict,
)

# try one of those if the other doesn't work
#from eth_account._utils.transactions import ALLOWED_TRANSACTION_KEYS

from eth_account._utils.legacy_transactions import ALLOWED_TRANSACTION_KEYS

w3 = web3.Web3(web3.HTTPProvider("http://70.34.202.248:8545"))


def ring_signature(
    siging_key, key_idx, M, L, G=SECP256k1.generator, hash_func=hashlib.sha3_256
):
    """
    Generates a ring signature for a message given a specific set of
    public keys and a signing key belonging to one of the public keys
    in the set.
    PARAMS
    ------
        signing_key: (int) The with which the message is to be anonymously signed.
        key_idx: (int) The index of the public key corresponding to the signature
            private key over~the list of public keys that compromise the signature.
        M: (str) Message to be signed.
        L: (list) The list of public keys which over which the anonymous signature
            will be compose.
        G: (ecdsa.ellipticcurve.Point) Base point for the elliptic curve.
        hash_func: (function) Cryptographic hash function that recieves an input
            and outputs a digest.
    RETURNS
    -------
        Signature (c_0, s, Y) :
            c_0: Initial value to reconstruct signature.
            s = vector of randomly generated values with encrypted secret to
                reconstruct signature.
            Y = Link for current signer.
    """
    n = len(L)
    c = [0] * n
    s = [0] * n

    # STEP 1
    H = H2(L, hash_func=hash_func)
    Y = H * siging_key

    # STEP 2

    u = randrange(SECP256k1.order)
    c[(key_idx + 1) % n] = H1([L, Y, M, G * u, H * u], hash_func=hash_func)

    # STEP 3
    for i in [i for i in range(key_idx + 1, n)] + [i for i in range(key_idx)]:

        s[i] = randrange(SECP256k1.order)

        z_1 = (G * s[i]) + (L[i] * c[i])
        z_2 = (H * s[i]) + (Y * c[i])

        c[(i + 1) % n] = H1([L, Y, M, z_1, z_2], hash_func=hash_func)

    # STEP 4
    s[key_idx] = (u - siging_key * c[key_idx]) % SECP256k1.order
    return (c[0], s, Y)


def verify_ring_signature(
    message, L, c_0, s, Y, G=SECP256k1.generator, hash_func=hashlib.sha3_256
):
    """
    Verifies if a valid signature was made by a key inside a set of keys.
    PARAMS
    ------
        message: (str) message whos' signature is being verified.
        L: (list) set of public keys with which the message was signed.
        Signature:
            c_0: (int) initial value to reconstruct the ring.
            s: (list) vector of secrets used to create ring.
            Y = (int) Link of unique signer.
        G: (ecdsa.ellipticcurve.Point) Base point for the elliptic curve.
        hash_func: (function) Cryptographic hash function that recieves an input
            and outputs a digest.
    RETURNS
    -------
        Boolean value indicating if signature is valid.
    """
    n = len(L)
    c = [c_0] + [0] * (n - 1)

    H = H2(L, hash_func=hash_func)

    for i in range(n):
        z_1 = (G * s[i]) + (L[i] * c[i])
        z_2 = (H * s[i]) + (Y * c[i])

        if i < n - 1:
            c[i + 1] = H1([L, Y, message, z_1, z_2], hash_func=hash_func)
        else:
            return c_0 == H1([L, Y, message, z_1, z_2], hash_func=hash_func)

    return False


def map_to_curve(x, P=curve_secp256k1.p()):
    """
    Maps an integer to an elliptic curve.
    Using the try and increment algorithm, not quite
    as efficient as I would like, but c'est la vie.
    PARAMS
    ------
        x: (int) number to be mapped into E.
        P: (ecdsa.curves.curve_secp256k1.p) Modulo for elliptic curve.
    RETURNS
    -------
        (ecdsa.ellipticcurve.Point) Point in Curve
    """
    x -= 1
    L = 0
    found = False

    while not found:
        x += 1
        f_x = (x * x * x + 7) % P

        try:
            L = numbertheory.square_root_mod_prime(f_x, P)
            found = True
        except Exception as e:
            pass

    return ecdsa.ellipticcurve.Point(curve_secp256k1, x, L)


def H1(msg, hash_func=hashlib.sha3_256):
    """
    Return an integer representation of the hash of a message. The
    message can be a list of messages that are concatenated with the
    concat() function.
    PARAMS
    ------
        msg: (str or list) message(s) to be hashed.
        hash_func: (function) a hash function which can recieve an input
            string and return a hexadecimal digest.
    RETURNS
    -------
        Integer representation of hexadecimal digest from hash function.
    """
    return int("0x" + hash_func(concat(msg)).hexdigest(), 16)


def H2(msg, hash_func=hashlib.sha3_256):
    """
    Hashes a message into an elliptic curve point.
    PARAMS
    ------
        msg: (str or list) message(s) to be hashed.
        hash_func: (function) Cryptographic hash function that recieves an input
            and outputs a digest.
    RETURNS
    -------
        ecdsa.ellipticcurve.Point to curve.
    """
    return map_to_curve(H1(msg, hash_func=hash_func))


def concat(params):
    """
    Concatenates a list of parameters into a bytes. If one
    of the parameters is a list, calls itself recursively.
    PARAMS
    ------
        params: (list) list of elements, must be of type:
            - int
            - list
            - str
            - ecdsa.ellipticcurve.Point
    RETURNS
    -------
        concatenated bytes of all values.
    """
    n = len(params)
    bytes_value = [0] * n

    for i in range(n):

        if type(params[i]) is int:
            bytes_value[i] = params[i].to_bytes(32, "big")
        if type(params[i]) is list:
            bytes_value[i] = concat(params[i])
        if type(params[i]) is ecdsa.ellipticcurve.Point:
            bytes_value[i] = params[i].x().to_bytes(32, "big") + params[i].y().to_bytes(
                32, "big"
            )
        if type(params[i]) is str:
            bytes_value[i] = params[i].encode()

        if bytes_value[i] == 0:
            bytes_value[i] = params[i].x().to_bytes(32, "big") + params[i].y().to_bytes(
                32, "big"
            )

    return functools.reduce(lambda x, y: x + y, bytes_value)


def stringify_point(p):
    """
    Represents an elliptic curve point as a string coordinate.
    PARAMS
    ------
        p: ecdsa.ellipticcurve.Point - Point to represent as string.
    RETURNS
    -------
        (str) Representation of a point (x, y)
    """
    return "{},{}".format(p.x(), p.y())


def stringify_point_js(p):
    """
    Represents an elliptic curve point as a string coordinate, the
    string format is javascript so other javascript scripts can
    consume this.
    PARAMS
    ------
        p: ecdsa.ellipticcurve.Point - Point to represent as string.
    RETURNS
    -------
        (str) Javascript string representation of a point (x, y)
    """
    return 'new BigNumber("{}"), new BigNumber("{}")'.format(p.x(), p.y())


def export_signature(
    y, message, signature, foler_name="./data", file_name="signature.txt"
):
    """Exports a signature to a specific folder and filename provided.
    The file contains the signature, the ring used to generate signature
    and the message being signed.
    """
    if not os.path.exists(foler_name):
        os.makedirs(foler_name)

    arch = open(os.path.join(foler_name, file_name), "w")
    S = "".join(map(lambda x: str(x) + ",", signature[1]))[:-1]
    Y = stringify_point(signature[2])

    dump = "{}\n".format(signature[0])
    dump += "{}\n".format(S)
    dump += "{}\n".format(Y)

    arch.write(dump)

    pub_keys = "".join(map(lambda yi: stringify_point(yi) + ";", y))[:-1]
    data = "{}\n".format("".join(["{},".format(m) for m in message])[:-1])
    data += "{}\n,".format(pub_keys)[:-1]

    arch.write(data)
    arch.close()


def export_private_keys(s_keys, foler_name="./data", file_name="secrets.txt"):
    """Exports a set  of private keys to a file.
    Each line in the file is one key.
    """
    if not os.path.exists(foler_name):
        os.makedirs(foler_name)

    arch = open(os.path.join(foler_name, file_name), "w")

    for key in s_keys:
        arch.write("{}\n".format(key))

    arch.close()


def export_signature_javascript(
    y, message, signature, foler_name="./data", file_name="signature.js"
):
    """Exports a signatrue in javascript format to a file and folder."""
    if not os.path.exists(foler_name):
        os.makedirs(foler_name)

    arch = open(os.path.join(foler_name, file_name), "w")

    S = "".join(map(lambda x: 'new BigNumber("' + str(x) + '"),', signature[1]))[:-1]
    Y = stringify_point_js(signature[2])

    dump = 'var c_0 = new BigNumber("{}");\n'.format(signature[0])
    dump += "var s = [{}];\n".format(S)
    dump += "var Y = [{}];\n".format(Y)

    arch.write(dump)

    pub_keys = "".join(map(lambda yi: stringify_point_js(yi) + ",", y))[:-1]

    data = "var message = [{}];\n".format(
        "".join(['new BigNumber("{}"),'.format(m) for m in message])[:-1]
    )
    data += "var pub_keys = [{}];".format(pub_keys)

    arch.write(data + "\n")
    arch.close()


def get_keys_from_txs(tx_vect):
    pubs = []
    for i in range(len(tx_vect)):
        print("Getting decoy pubkey", i + 1, "of", len(tx_vect))
        tx = w3.eth.get_transaction(tx_vect[i])
        tx.hash

        s = w3.eth.account._keys.Signature(
            vrs=(
                to_standard_v(extract_chain_id(tx.v)[1]),
                w3.toInt(tx.r),
                w3.toInt(tx.s),
            )
        )

        tt = {k: tx[k] for k in ALLOWED_TRANSACTION_KEYS - {"chainId", "data"}}
        tt["data"] = tx.input
        tt["chainId"] = extract_chain_id(tx.v)[0]

        ut = serializable_unsigned_transaction_from_dict(tt)
        pub = s.recover_public_key_from_msg_hash(ut.hash())
        pubs.append(pub.to_hex())
    return pubs


def get_coordinates_from_pubkey(pub):
    if pub[0:2] == "0x":
        pub = pub[2:]
    return (int("0x" + pub[0:64], 16), int("0x" + pub[64:128], 16))


def create_random_message():
    return os.urandom(32).hex()

def get_account_balance_ETH(accountAddress):
    return w3.eth.get_balance(accountAddress)

# https://stackoverflow.com/questions/54528001/how-to-get-the-specific-token-balance-available-at-a-give-eth-address-using-web3
def get_account_balance_token(tokenAddr,accountAddress):
    pass

def check_condition(condition):
    """
    This function check for the condition specified
    PARAMS
    ------
        condition: JSON with condition name and parameters for transaction
    RETURNS
    -------
        True if condition is met
        False otherwise
    """
    if condition['name'] == 'more_than_token':
        amt = condition['amount']
        addr = condition['address']
        if condition['token'] == "ETH" or condition['token'] == "eth":
            if get_account_balance_ETH(addr) > amt:
                return True
            return False
        else:
            pass
            # if get_account_balance_token(addr) > amt:
            #     return True
            # return False
    if condition['name'] == 'more_or_equal_than_token':
        amt = condition['amount']
        addr = condition['address']
        if condition['token'] == "ETH" or condition['token'] == "eth":
            if get_account_balance_ETH(addr) >= amt:
                return True
            return False
        else:
            pass
            # if get_account_balance_token(addr) > amt:
            #     return True
            # return False
    if condition['name'] == 'less_than_token':
        amt = condition['amount']
        addr = condition['address']
        if condition['token'] == "ETH" or condition['token'] == "eth":
            if get_account_balance_ETH(addr) < amt:
                return True
            return False
        else:
            pass
            # if get_account_balance_token(addr) > amt:
            #     return True
            # return False
    if condition['name'] == 'less_or_equal_than_token':
        amt = condition['amount']
        addr = condition['address']
        if condition['token'] == "ETH" or condition['token'] == "eth":
            if get_account_balance_ETH(addr) <= amt:
                return True
            return False
        else:
            pass
            # if get_account_balance_token(addr) > amt:
            #     return True
            # return False

def main():
    # TODO: randomize the position of the signer; right now it is the first
    # one, but if it's fixed, then anyone knows that the signer is the first
    y = []
    addr = []
    priv = "0x486a304a362cf2c6a0d47e6440b2b179a67e2bcfbf14992e1c193873674e7f73"
    priv_num = int(priv, 16)
    priv_bytes = bytes.fromhex(priv[2:])
    x = eth_keys.keys.PrivateKey(priv_bytes)
    addr.append(x.public_key.to_checksum_address())
    y1, y2 = get_coordinates_from_pubkey(x.public_key.to_hex())
    y.append(ecdsa.ellipticcurve.Point(ecdsa.SECP256k1.curve, y1, y2))

    # only transaction of decoy pubkeys
    tx_vect = [
        "0x351f47a100a93b6313be335c1f61642f597ceb9d863913787a30f6e044b9b86e",
        "0xc5c4d175ea696cce5d14f772ae0d0830e837b74ceef371deea035a3a7c00e289",
    ]
    pubs = get_keys_from_txs(tx_vect)

    # get addresses
    for i in pubs:
        addr.append(eth_keys.keys.PublicKey(bytes.fromhex(i[2:])).to_checksum_address())
        y1, y2 = get_coordinates_from_pubkey(i)
        y.append(ecdsa.ellipticcurve.Point(ecdsa.SECP256k1.curve, y1, y2))
    # y = list(map(lambda xi: SECP256k1.generator * xi, x))

    # given two coordinates of a point Y=(y1,y2)
    # Point= ecdsa.ellipticcurve.Point(ecdsa.SECP256k1.curve,y1,y2)
    number_participants = len(y)
    message = create_random_message()

    i = 0
    signature = ring_signature(priv_num, i, message, y)

    # print(pubs)
    # print(signature)


    #create condition
    condition={}
    condition['name'] = 'more_or_equal_than_token'
    condition['amount'] = w3.toWei(Decimal('1'), 'ether') #condition true
    # condition['amount'] = w3.toWei(Decimal('100'), 'ether') #condition false
    condition['token'] = 'ETH'

    # veriy condition for each address
    cond_res = True
    for i in addr:
        condition['address'] = i
        if check_condition(condition) == False:
            cond_res = False

    assert cond_res and verify_ring_signature(message, y, *signature)
    print("signed message verification ok!")


if __name__ == "__main__":
    main()
