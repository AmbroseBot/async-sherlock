import asyncio
import os
from pprint import pprint

from sherlock import Sherlock


async def main():
    sherlock: Sherlock = Sherlock(os.getcwd())
    result = await sherlock.request("query")
    pprint(result.found)
    await sherlock.underlying_session.aclose()


asyncio.run(main())
