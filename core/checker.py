import asyncio

import base58
from curl_cffi.requests import AsyncSession, Response
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_account.signers.local import LocalAccount
from loguru import logger
from solders.keypair import Keypair
from tenacity import retry

from utils import append_file, get_proxy, loader, get_account

Account.enable_unaudited_hdwallet_features()


def log_retry_error(retry_state):
    logger.error(retry_state.outcome.exception())


class Checker:
    def __init__(self,
                 solana_keypair: Keypair | None = None,
                 evm_account: LocalAccount | None = None):
        self.solana_keypair: Keypair | None = solana_keypair
        self.evm_account: LocalAccount | None = evm_account

        self.log_address: str = str(self.solana_keypair.pubkey()) if self.solana_keypair else self.evm_account.address

    @retry(after=log_retry_error)
    async def _get_eligibility(self,
                               auth_token: str) -> tuple[int, int]:
        response_text: None = None

        try:
            async with AsyncSession(impersonate='chrome124') as client:
                r: Response = await client.post(
                    url='https://api.clusters.xyz/v0.1/airdrops/pengu/eligibility',
                    json=[auth_token],
                    proxy=get_proxy(),
                    headers={
                        'content-type': 'application/json'
                    }
                )

                response_text: str = r.text

                if '<title>Access denied |' in response_text:
                    response_text: None = None
                    raise Exception(f'{self.log_address} | CloudFlare')

                return r.json()['total'], r.json()['totalUnclaimed']

        except Exception as error:
            raise Exception(
                f'{self.log_address} | Unexpected Error When Getting Eligibility: {error}'
                + (f', response: {response_text}' if response_text else '')
            ) from error

    @retry(after=log_retry_error)
    async def _get_sign(self) -> tuple[str, str]:
        response_text: None = None

        try:
            async with AsyncSession(impersonate='chrome124') as client:
                r: Response = await client.get(
                    url='https://api.clusters.xyz/v0.1/airdrops/pengu/auth/message?',
                    proxy=get_proxy()
                )

                response_text: str = r.text

                if '<title>Access denied |' in response_text:
                    response_text: None = None
                    raise Exception(f'{self.log_address} | CloudFlare')

                return r.json()['message'], r.json()['signingDate']

        except Exception as error:
            raise Exception(
                f'{self.log_address} | Unexpected Error When Getting Sign Text: {error}'
                + (f', response: {response_text}' if response_text else '')
            ) from error

    @retry(after=log_retry_error)
    async def _get_auth_token(self,
                              sign_hash: str,
                              sign_date: str) -> str:
        if self.evm_account:
            payload: dict = {
                'signature': sign_hash,
                'signingDate': sign_date,
                'type': 'evm',
                'wallet': self.log_address
            }

        else:
            payload: dict = {
                'signature': sign_hash,
                'signingDate': sign_date,
                'type': 'solana',
                'wallet': self.log_address
            }

        response_text: None = None

        try:
            async with AsyncSession(impersonate='chrome124') as client:
                r: Response = await client.post(
                    url='https://api.clusters.xyz/v0.1/airdrops/pengu/auth/token?',
                    json=payload,
                    proxy=get_proxy()
                )

                response_text: str = r.text

                if '<title>Access denied |' in response_text:
                    response_text: None = None
                    raise Exception(f'{self.log_address} | CloudFlare')

                if not r.json()['isValid']:
                    raise Exception(
                        f'{self.log_address} | Wrong Response When Getting Auth Token, response: {response_text}')

                return r.json()['token']

        except Exception as error:
            raise Exception(
                f'{self.log_address} | Unexpected Error When Getting Auth Token: {error}'
                + (f', response: {response_text}' if response_text else '')
            ) from error

    async def balance_checker(self) -> None:
        sign_text, sign_date = await self._get_sign()

        if self.evm_account:
            sign_hash: str = self.evm_account.sign_message(
                signable_message=encode_defunct(text=sign_text)).signature.hex()
            sign_hash: str = sign_hash if sign_hash.startswith('0x') else f'0x{sign_hash}'

        else:
            sign_hash: str = f'0x{bytes(self.solana_keypair.sign_message(message=sign_text.encode())).hex()}'

        auth_token: str = await self._get_auth_token(sign_hash=sign_hash,
                                                     sign_date=sign_date)

        account_balance, unclaimed_balance = await self._get_eligibility(auth_token=auth_token)

        if unclaimed_balance <= 0:
            logger.error(f'{self.log_address} | Not Eligible')
            return

        logger.success(f'{self.log_address} | Available: {unclaimed_balance} $PENGU | Total: {account_balance} '
                       f'$PENGU')

        async with asyncio.Lock():
            if self.evm_account:
                await append_file(
                    file_path='result/with_balances_evm.txt',
                    file_content=f'{self.evm_account.address} | {self.evm_account.key.hex()} | {unclaimed_balance} $PENGU\n'
                )

            elif self.solana_keypair:
                await append_file(
                    file_path='result/with_balances_sol.txt',
                    file_content=f'{str(self.solana_keypair.pubkey())} | '
                                 f'{base58.b58encode(bytes(self.solana_keypair.to_bytes_array())).decode("utf-8")} | '
                                 f'{unclaimed_balance} $PENGU\n'
                )


async def check_account(
        account_data: str
) -> None:
    async with loader.semaphore:
        account_type, account = get_account(account_data=account_data)

        if account_type == 1:
            checker: Checker = Checker(
                evm_account=account
            )

        elif account_type == 2:
            checker: Checker = Checker(
                solana_keypair=account
            )

        else:
            logger.error(f'{account_data} | Not Valid SOL/EVM PKey / Mnemonic')
            return

        return await checker.balance_checker()
