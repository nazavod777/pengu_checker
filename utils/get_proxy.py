from random import choice

from better_proxy import Proxy

with open(
        file='data/proxies.txt',
        mode='r',
        encoding='utf-8-sig'
) as file:
    proxy_list: list[str] = [Proxy.from_str(proxy=row.strip()
    if '://' in row.strip() else f'http://{row.strip()}').as_url
                             for row in file if row]


def get_proxy() -> str | None:
    return choice(proxy_list) if proxy_list else None
