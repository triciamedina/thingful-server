const AuthService = require('../auth/auth-service')

function requireAuth (req, res, next) {
    // saves Authorization header
    const authToken = req.get('Authorization') || ''

    let bearerToken

    // checks if Authorization headers begins with 'bearer '
    if (!authToken.toLowerCase().startsWith('bearer ')) {
        return res.status(401).json({ error: 'Missing bearer token' })
    } else {
        // extracts token from the string
        bearerToken = authToken.slice(7, authToken.length)
    }

    try {
        // verifies JWT
        // jwt.verfiy() returns payload/user info?
        const payload = AuthService.verifyJwt(bearerToken)
        // Checks databse for matching user and returns user. Payload.sub is user_name
        AuthService.getUserWithUserName(
            req.app.get('db'),
            payload.sub,
        )
            .then(user => {
                if (!user) {
                    return res.status(401).json({ error: 'Unauthorized request' })
                }
                // sets req.user to user returned from db
                req.user = user
                next()
            })
            .catch(err => {
                console.error(err)
                next(err)
            })
    } catch (error) {
        res.status(401).json({ error: 'Unauthorized request' })
    }
}

module.exports = {
    requireAuth,
}