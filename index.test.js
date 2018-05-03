import {
    hashPassword,
    verifyPassword,
    hashSessionIdentifier,
    createSessionIdentifier,
    createNewJWTToken,
    getJWTSecret,
    setAppSecret,
} from './index'
import jwt from 'jsonwebtoken'

beforeEach(() => {
    setAppSecret('32deab387e5378cfab994a4c98ea4e3370edfe8ba8e3c69fe5d0c11d9685f788')
});

test('a hashed password should be able to be verfied', async () => {
    const password = 'hunter2'
    const hash = await hashPassword(password)

    expect(await verifyPassword(hash, password)).toBe(true)
})

test('a hashed session identifier should be able to be rehashed and verfied', async () => {
    const sessionIdentifier = await createSessionIdentifier()

    const hash = await hashSessionIdentifier(sessionIdentifier)
    const hash2 = await hashSessionIdentifier(sessionIdentifier)

    expect(sessionIdentifier).not.toEqual(hash)
    expect(hash).toEqual(hash2)
});

test('two different sessions should not be the same', async () => {
    const sessionIdentifier = await createSessionIdentifier()
    const sessionIdentifier2 = await createSessionIdentifier()

    const hash = await hashSessionIdentifier(sessionIdentifier)
    const hash2 = await hashSessionIdentifier(sessionIdentifier2)

    expect(hash).not.toEqual(hash2)
});

test('a hashed session identifier should not be the same after changing the app key', async () => {
    const sessionIdentifier = await createSessionIdentifier()

    const hash = await hashSessionIdentifier(sessionIdentifier)
    setAppSecret('foo')
    const hash2 = await hashSessionIdentifier(sessionIdentifier)

    expect(sessionIdentifier).not.toEqual(hash)
    expect(hash).not.toEqual(hash2)
});

test('it should be able to create a JWT and decode a it to get the session identifier', async () => {
    const password = 'hunter2'
    const sessionIdentifier = await createSessionIdentifier()
    const passwordHash = await hashPassword(password)
    const sessionHash = await hashSessionIdentifier(sessionIdentifier)

    const userData = {
        sessionIdentifier,
    }

    const token = await createNewJWTToken(userData, passwordHash, sessionHash)
    const decodedToken = jwt.decode(token)

    expect(decodedToken.sessionIdentifier).toEqual(userData.sessionIdentifier)
})

test('it should be able verify a JWT', async () => {
    const password = 'hunter2'
    const sessionIdentifier = await createSessionIdentifier()
    const passwordHash = await hashPassword(password)
    const sessionHash = await hashSessionIdentifier(sessionIdentifier)

    const userData = {
        sessionIdentifier,
    }

    const secret = getJWTSecret(passwordHash, sessionHash)

    const token = await createNewJWTToken(userData, passwordHash, sessionHash)

    expect(() => {
        jwt.verify(token, secret)
    }).not.toThrowError(jwt.JsonWebTokenError)
})

test('it should not be able verify a JWT with an invalid secret', async () => {
    const password = 'hunter2'
    const sessionIdentifier = await createSessionIdentifier()
    const passwordHash = await hashPassword(password)
    const sessionHash = await hashSessionIdentifier(sessionIdentifier)

    const userData = {
        sessionIdentifier,
    }

    const secret = 'not-a-valid-secret'

    const token = await createNewJWTToken(userData, passwordHash, sessionHash)

    expect(() => {
        jwt.verify(token, secret)
    }).toThrowError(jwt.JsonWebTokenError)
})

test('it should not be able verify a JWT with an new password hash', async () => {
    const password = 'hunter2'
    const sessionIdentifier = await createSessionIdentifier()
    const passwordHash = await hashPassword(password)
    const sessionHash = await hashSessionIdentifier(sessionIdentifier)

    const userData = {
        sessionIdentifier,
    }

    const token = await createNewJWTToken(userData, passwordHash, sessionHash)

    const newPasswordHash = await hashPassword(password)
    const secret = getJWTSecret(newPasswordHash, sessionHash)

    expect(() => {
        jwt.verify(token, secret)
    }).toThrowError(jwt.JsonWebTokenError)
})

test('it should not be able verify a JWT with an new session hash', async () => {
    const password = 'hunter2'
    const sessionIdentifier = await createSessionIdentifier()

    const passwordHash = await hashPassword(password)
    const sessionHash = await hashSessionIdentifier(sessionIdentifier)

    const userData = {
        sessionIdentifier,
    }

    const token = await createNewJWTToken(userData, passwordHash, sessionHash)

    const newSessionIdentifier = await createSessionIdentifier()

    const newSessionHash = await hashSessionIdentifier(newSessionIdentifier)
    const secret = getJWTSecret(passwordHash, newSessionHash)

    expect(() => {
        jwt.verify(token, secret)
    }).toThrowError(jwt.JsonWebTokenError)
})

test('it should not be able verify a JWT when the app secret is changed', async () => {
    const password = 'hunter2'
    const sessionIdentifier = await createSessionIdentifier()
    const passwordHash = await hashPassword(password)
    const sessionHash = await hashSessionIdentifier(sessionIdentifier)

    const userData = {
        sessionIdentifier,
    }

    const token = await createNewJWTToken(userData, passwordHash, sessionHash)

    setAppSecret('changed-secret')

    const secret = getJWTSecret(passwordHash, sessionHash)

    expect(() => {
        jwt.verify(token, secret)
    }).toThrowError(jwt.JsonWebTokenError)
})
