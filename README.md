# Proof of concept: Securely invalidate JWT sessions

![https://i.imgur.com/OrvY8kN.png](https://i.imgur.com/OrvY8kN.png)

install dependencies & run tests

```
yarn
yarn jest
```

# Implementation:

#### On successfull login:

1. Create a new session identifier (sid) (`crypto.randomBytes`)
2. Hash the sid (`createHmac('sha256', appSecret)`)
3. Save the hashed sid to the database with the user id (optionally add an expires date).
4. Create a JWT, with the sid as payload and sign it with a secret composed of the users password hash, the hashed sid and the app secret:
    ```
    jwt.sign({ sid }, `${passwordHash}${hashedSid}${appSecret}`)
    ```

Siging the JWT with an combination of the passwordHash, hashedSid and app secrets results in a couple of things:

1. When the user changes his or her password the token becomes invalid.
2. When the session is removed from the database, expired or is tampered with the token becomes invalid.
3. No two login with the same user will have the same JWT token or session.
4. When the app secret changes or tokens are used in another environment the token becomes invalid.

#### on auth request:

1. Decode the JWT and retrieve the session identifier (sid)
2. Hash the sid
3. Find a session in the database
 - If not found: throw an Auth error
4. Use the user id to retrieve the password hash from the db
5. Verify the JWT with the session hash, password hash and app secret
 - If invalid: throw an Auth error

# Caveats

Siging the JWT with the password requires a strategy to send a new token to the user if the user changes his or her password while logged in (ex. via a settings screen). If the user does not get a new JWT any new requests will be unauthorized.

Only siging a JWT with the session hash and app secret might be enough, however you need to manually invalidate sessions in the db when a user changes his password.
