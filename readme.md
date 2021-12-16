Async Sherlock
--------------

This project is simply [Sherlock](https://github.com/sherlock-project/sherlock) 
ported to work in an asynchronous environment and within embedded applications
rather than the command line.

---

The `data.json` file has been modified for my own usage, if you want
the original functionality please copy the sherlock one. 

---

Side note, kinda dodge implementation. Didn't want to
actually rewrite everything so its uses the same internal
logic, just wrapped with an async request base and `asyncio.gather`
for them speedups