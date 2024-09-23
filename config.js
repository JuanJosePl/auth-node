export const {
  PORT = 3000,
  SALT_ROUNDS = 10,
  SECRET_JWT_KEY = 'this-is-an-awesome-secret-key-mucho-mas-largo',
  SECRET_REFRESH_KEY = 'this-is-another-secret-key-for-refresh-tokens'
} = process.env
