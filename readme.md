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

---

Heres a little speed comparison:

| Client   | Speed       |
|----------|-------------|
| Sherlock | ~20 Seconds |
| This     | ~5 Seconds  |

Plus you get the added benefit that you can easily embed this 
into your applications rather than being restricted to command line.

---

Licensing, usage, etc is the same as [Sherlock](https://github.com/sherlock-project/sherlock).
Please refer to that repo in that regard.