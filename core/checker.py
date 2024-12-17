import asyncio

from curl_cffi.requests import AsyncSession, Response
from eth_account import Account
from loguru import logger
from tenacity import retry
from web3.auto import w3

from utils import append_file
from utils import get_proxy
from utils import loader

Account.enable_unaudited_hdwallet_features()


class CloudFlareError(BaseException):
    pass


def log_retry_error(retry_state):
    logger.error(retry_state.outcome.exception())


class Checker:
    def __init__(self,
                 account_address: str,
                 account_data: str):
        self.account_address: str = account_address
        self.account_data: str = account_data

    @retry(after=log_retry_error)
    async def _get_balance(self) -> tuple[int, int]:
        response_text: None = None

        try:
            async with AsyncSession(impersonate='chrome124') as client:
                response_text: None = None

                r: Response = await client.get(
                    url=f'https://api.clusters.xyz/v0.1/airdrops/pengu/eligibility/{w3.to_checksum_address(value=self.account_address)}?',
                    proxy=get_proxy(),
                    headers={
                        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                        'accept-language': 'ru,en;q=0.9',
                    },
                    timeout=15
                )

            if '<title>Access denied |' in r.text:
                raise Exception(f'{self.account_address} | CloudFlare')

            response_text: str = r.text
            response_json: dict = r.json()

            return response_json['total'], response_json['totalUnclaimed']

        except Exception as error:
            raise Exception(
                f'{self.account_address} | Unexpected Error When Checking Eligible: {error}'
                + (f', response: {response_text}' if response_text else '')
            ) from error

    async def balance_checker(self) -> None:
        account_balance, unclaimed_balance = await self._get_balance()

        if account_balance <= 0:
            logger.error(f'{self.account_address} | Not Eligible')
            return

        if unclaimed_balance <= 0:
            logger.info(f'{self.account_address} | Claimed')
            return

        logger.success(f'{self.account_address} | {self.account_data} | {account_balance} $PENGU')

        async with asyncio.Lock():
            await append_file(
                file_path='result/with_balances.txt',
                file_content=f'{self.account_address} | {self.account_data} | {account_balance} $PENGU\n'
            )


async def check_account(
        account_data: str
) -> None:
    async with loader.semaphore:
        account_address: None = None

        try:
            account_address: str = Account.from_key(private_key=account_data).address

        except Exception:
            pass

        if not account_address:
            try:
                account_address: str = Account.from_mnemonic(mnemonic=account_data).address

            except Exception:
                pass

        if not account_address:
            try:
                account_address: str = w3.to_checksum_address(value=account_data)

            except Exception:
                pass

        if not account_address:
            logger.error(f'{account_data} | Not Mnemonic and not PKey')
            return

        checker: Checker = Checker(
            account_address=account_address,
            account_data=account_data
        )

        return await checker.balance_checker()
