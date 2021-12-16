import os
import asyncio
from pprint import pprint

from sherlock import Sherlock


async def main():
    sherlock: Sherlock = Sherlock(os.getcwd())
    result = await sherlock.request("Query here")
    pprint(result)


asyncio.run(main())
