
# copied values from electrum source

# IDK, maybe?
ELECTRUM_VERSION = '2.6.4'  # version of the client package
PROTOCOL_VERSION = '0.10'   # protocol version requested

# monacoin address type
ADDRTYPE_P2PKH = 50
ADDRTYPE_P2SH = 55
ADDRTYPE_P2SH_ALT = 5
SEGWIT_HRP = "mona"

# note: 'v' and 'p' are effectively reserved as well.
PROTOCOL_CODES = dict(t='TCP (plaintext)', h='HTTP (plaintext)', s='SSL', g='Websocket')

# from electrum/lib/network.py at Jun/2016
#
DEFAULT_PORTS = { 't':50001, 's':50002, 'h':8081, 'g':8082}

BOOTSTRAP_SERVERS = {
    'electrumx.tamami-foundation.org': {'t':50001, 's':50002},
    'electrumx2.tamami-foundation.org': {'t':50001, 's':50002},
    'electrumx3.tamami-foundation.org': {'t':50001, 's':50002},
    'electrumx2.monacoin.nl': {'t':50001, 's':50002},
    'electrumx3.monacoin.nl': {'t':50001, 's':50002},
    'electrumx1.monacoin.ninja': {'t':50001, 's':50002},
    'electrumx2.monacoin.ninja': {'t':50001, 's':50002},
    'electrumx2.movsign.info': {'t':50001, 's':50002},
    'ri7rzlmdaf4eqbza.onion': {'t':50001, 's':50002},
    'electrum-mona.bitbank.cc': {'t':50001, 's':50002},
}



