1) zeorize sensitive data in memory
2) bind funcs on syscalls (kill and others)
3) logging!!!
4) maybe creds politics? restrictions to password and ttl for them.
5) prevent timing attacks by setting const time for auths and other
6) expand user struct with token_max_ttl, token_num_uses, token_bound_cirds
7) -> Self for every new func
8) there are probably places, where you can pass poinetrs instead pointed values
9) cipher objects on serde::Serialize and serde::Deserialize
10) Maybe desribe errors better? now it encapsulates in higher level and passes.
11) btw i think better to store engines in observer and authmethods in user in Hashmap<AuthMethod, bool> e.t.c.
12) use nonce in aes as intended? that won't give any help on small data amounts, because every encrypted secret, 
    user or token is guaranteed unique, and that fulfills the avalanche effect.
13) write new methods where needed, don't create instances using public struct members
14) for now mount paths are fictional, different secret engines are separated anyway
15) unify errors