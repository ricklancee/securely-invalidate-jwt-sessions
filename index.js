import { randomBytes, createHmac } from 'crypto'
import { hash, verify } from 'argon2'
import { sign } from 'jsonwebtoken'

let wowMuchSecretVerySecure = '32deab387e5378cfab994a4c98ea4e3370edfe8ba8e3c69fe5d0c11d9685f788'

const getAppSecret = () => wowMuchSecretVerySecure
export const setAppSecret = (secret) => wowMuchSecretVerySecure = secret

export const createSessionIdentifier = () => new Promise((resolve, reject) => {
    randomBytes(32, (err, buffer) => {
        if (err) {
            reject(err)
            return
        }

        resolve(buffer.toString('hex'))
    })
})

export const hashPassword = (string) =>
    hash(string)
export const verifyPassword = (hash, string) =>
    verify(hash, string)

export const hashSessionIdentifier = (sessionIdentifier) =>
    createHmac('sha256', getAppSecret())
        .update(sessionIdentifier)
        .digest('hex')

export const createNewJWTToken = async (userData, passwordHash, sessionHash) =>
    sign(userData, getJWTSecret(passwordHash, sessionHash))

export const getJWTSecret = (passwordHash, sessionHash) => `${wowMuchSecretVerySecure}${passwordHash}${sessionHash}`
