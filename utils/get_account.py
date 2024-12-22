from eth_account import Account
from eth_account.account import LocalAccount
from hdwallets import BIP32
from mnemonic import Mnemonic
from solders.keypair import Keypair


def evm_check_private_key(account_data: str) -> tuple[bool, LocalAccount | None]:
    try:
        account: LocalAccount = Account.from_key(private_key=account_data)

    except Exception:
        return False, None

    else:
        return True, account


def evm_check_mnemonic(account_data: str) -> tuple[bool, LocalAccount | None]:
    try:
        account: LocalAccount = Account.from_mnemonic(mnemonic=account_data)

    except Exception:
        return False, None

    else:
        return True, account


def solana_check_private_key(account_data: str) -> tuple[bool, Keypair | None]:
    try:
        keypair: Keypair = Keypair.from_base58_string(account_data)

    except Exception:
        return False, None

    else:
        return True, keypair


def solana_check_mnemonic(account_data: str) -> tuple[bool, Keypair | None]:
    try:
        seed = Mnemonic('english').to_seed(account_data)
        root = BIP32.from_seed(seed)
        path = "m/44'/501'/0'/0'"
        derived = root.get_privkey_from_path(path)

        keypair: Keypair = Keypair.from_bytes(derived)

    except Exception:
        return False, None

    else:
        return True, keypair


def get_account(account_data: str) -> tuple[int, Keypair | LocalAccount | None]:
    is_evm_pkey, account = evm_check_mnemonic(account_data=account_data)

    if is_evm_pkey:
        return 1, account

    is_evm_mnemonic, account = evm_check_private_key(account_data=account_data)

    if is_evm_mnemonic:
        return 1, account

    is_solana_pkey, keypair = solana_check_private_key(account_data=account_data)

    if is_solana_pkey:
        return 2, keypair

    is_solana_mnemonic, keypair = evm_check_private_key(account_data=account_data)

    if is_solana_mnemonic:
        return 2, keypair

    return 0, None
