import express from 'express'
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser'
import { PORT, SECRET_JWT_KEY, SECRET_REFRESH_KEY } from './config.js'
import { UserRepositary } from './user-repository.js'

const app = express()

app.set('view engine', 'ejs')

app.use(express.json())
app.use(cookieParser())

app.use((req, res, next) => {
  const token = req.cookies.access_token

  req.session = { user: null }

  if (token) {
    try {
      const data = jwt.verify(token, SECRET_JWT_KEY)
      req.session.user = data
    } catch (error) {
      if (error.name === 'TokenExpiredError' && req.path !== '/refresh-token') {
        return res.status(401).send('Access token expired, please refresh')
      }
    }
  }

  next()
})

app.get('/', (req, res) => {
  const { user } = req.session
  res.render('example', user)
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body

  try {
    const user = await UserRepositary.login({ username, password })
    const accessToken = jwt.sign(
      { id: user._id, username: user.username },
      SECRET_JWT_KEY,
      { expiresIn: '10s' } // Acceso más corto, por ejemplo, 15 minutos
    )

    const refreshToken = jwt.sign(
      { id: user._id, username: user.username },
      SECRET_REFRESH_KEY,
      { expiresIn: '7d' } // Refresh token más largo, por ejemplo, 7 días
    )

    res
      .cookie('access_token', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000
      })
      .cookie('refresh_token', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 días
      })
      .send({ user, accessToken, refreshToken })
  } catch (error) {
    res.status(401).send(error.message)
  }
})

app.post('/refresh-token', (req, res) => {
  const refreshToken = req.cookies.refresh_token

  if (!refreshToken) return res.status(401).send('No refresh token provided')

  try {
    const userData = jwt.verify(refreshToken, SECRET_REFRESH_KEY)
    const newAccessToken = jwt.sign(
      { id: userData.id, username: userData.username },
      SECRET_JWT_KEY,
      { expiresIn: '1h' }
    )

    res.cookie('access_token', newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60 * 1000 // 1 hora
    }).send({ accessToken: newAccessToken })
  } catch (error) {
    return res.status(403).send('Invalid refresh token')
  }
})

app.post('/register', async (req, res) => {
  const { username, password } = req.body
  console.log(req.body)

  try {
    const id = await UserRepositary.create({ username, password })
    res.send({ id })
  } catch (error) {
    // NORMALMENTE NO ES BUENA IDEA MANDAR EL ERROR DEL REPOSITORIO
    res.status(400).send(error.message)
  }
})
app.post('/logout', (req, res) => {
  res
    .clearCookie('access_token')
    .clearCookie('refresh_token')
    .json({ message: 'Logout successful' })
})

app.get('/protected', (req, res) => {
  const { user } = req.session
  if (!user) return res.status(403).send('Access not authorized')
  res.render('protected', user)
})

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`)
})
// REFRESH TOKENS, PASSPORT, AUTH 2.0
