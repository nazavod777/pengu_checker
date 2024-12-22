import asyncio

from curl_cffi.requests import AsyncSession, Response
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_account.signers.local import LocalAccount
from loguru import logger
from tenacity import retry

from utils import append_file
from utils import get_proxy
from utils import loader

Account.enable_unaudited_hdwallet_features()


def log_retry_error(retry_state):
    logger.error(retry_state.outcome.exception())


class Checker:
    def __init__(self,
                 account: LocalAccount):
        self.account: LocalAccount = account

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
                    raise Exception(f'{self.account.address} | CloudFlare')

                return r.json()['total'], r.json()['totalUnclaimed']

        except Exception as error:
            raise Exception(
                f'{self.account.address} | Unexpected Error When Getting Eligibility: {error}'
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
                    raise Exception(f'{self.account.address} | CloudFlare')

                return r.json()['message'], r.json()['signingDate']

        except Exception as error:
            raise Exception(
                f'{self.account.address} | Unexpected Error When Getting Sign Text: {error}'
                + (f', response: {response_text}' if response_text else '')
            ) from error

    @retry(after=log_retry_error)
    async def _get_auth_token(self,
                              sign_hash: str,
                              sign_date: str) -> str:
        response_text: None = None

        try:
            async with AsyncSession(impersonate='chrome124') as client:
                r: Response = await client.post(
                    url='https://api.clusters.xyz/v0.1/airdrops/pengu/auth/token?',
                    json={
                        'signature': sign_hash,
                        'signingDate': sign_date,
                        'type': 'evm',
                        'wallet': self.account.address
                    },
                    proxy=get_proxy()
                )

                response_text: str = r.text

                if '<title>Access denied |' in response_text:
                    raise Exception(f'{self.account.address} | CloudFlare')

                if not r.json()['isValid']:
                    raise Exception(
                        f'{self.account.address} | Wrong Response When Getting Auth Token, response: {response_text}')

                return r.json()['token']

        except Exception as error:
            raise Exception(
                f'{self.account.address} | Unexpected Error When Getting Auth Token: {error}'
                + (f', response: {response_text}' if response_text else '')
            ) from error

    async def balance_checker(self) -> None:
        sign_text, sign_date = await self._get_sign()
        sign_hash: str = self.account.sign_message(signable_message=encode_defunct(text=sign_text)).signature.hex()
        sign_hash: str = sign_hash if sign_hash.startswith('0x') else f'0x{sign_hash}'

        auth_token: str = await self._get_auth_token(sign_hash=sign_hash,
                                                     sign_date=sign_date)

        account_balance, unclaimed_balance = await self._get_eligibility(auth_token=auth_token)
        available_balance: int = account_balance - unclaimed_balance

        if available_balance <= 0:
            logger.error(f'{self.account.address} | Not Eligible')
            return

        logger.success(f'{self.account.address} | Available: {available_balance} $PENGU | Total: {account_balance} '
                       f'$PENGU | Unclaimed: {unclaimed_balance} $PENGU')

        async with asyncio.Lock():
            await append_file(
                file_path='result/with_balances.txt',
                file_content=f'{self.account.address} | {self.account.key.hex()} | {available_balance} $PENGU\n'
            )


async def check_account(
        account_data: str
) -> None:
    async with loader.semaphore:
        account: None = None

        try:
            account: LocalAccount = Account.from_key(private_key=account_data)

        except Exception:
            pass

        if not account:
            try:
                account: LocalAccount = Account.from_mnemonic(mnemonic=account_data)

            except Exception:
                pass

        if not account:
            logger.error(f'{account_data} | Not Mnemonic and not PKey')
            return

        checker: Checker = Checker(
            account=account
        )

        return await checker.balance_checker()
