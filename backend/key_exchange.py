
import random


def simulate_dh(data):
    P = int(data.get('P'))
    G = int(data.get('G'))

    a = random.randint(2, P-2)
    b = random.randint(2, P-2)

    A_public = pow(G, a, P)
    B_public = pow(G, b, P)
    shared_key_User1 = pow(B_public, a, P)
    shared_key_User2 = pow(A_public, b, P)

    steps = [
        f"Prime P = {P}, Generator G = {G}",
        f"User1 selects private key a = {a}",
        f"User2 selects private key b = {b}",
        f"User1 computes public key A = {A_public} and sends to User2",
        f"User2 computes public key B = {B_public} and sends to User1",
        f"User1 computes shared key = {shared_key_User1}",
        f"User2 computes shared key = {shared_key_User2}",
        f"Both shared keys match? {'Yes' if shared_key_User1 == shared_key_User2 else 'No'}"
    ]

    return {
        "P": P,
        "G": G,
        "a": a,
        "b": b,
        "public_A": A_public,
        "public_B": B_public,
        "shared_key_User1": shared_key_User1,
        "shared_key_User2": shared_key_User2,
        "steps": steps,
        "status": "success"
    }
