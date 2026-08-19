# JWT_UV

This project implements a JWT (JSON Web Token) based authentication system with rate limiting.

## Rate Limiting

To prevent abuse and ensure fair usage, the application employs several rate limiting mechanisms:

### IP Rate Limit
Requests are limited per IP address to prevent a single client from overwhelming the system. The `check_rate_limit` function is used with the key `login:ip:{client_ip}` and limits defined by `settings.LOGIN_IP_LIMIT` within a window of `settings.RATE_LIMIT_WINDOW_SECONDS`.

### Email Rate Limit
To protect against brute-force attacks on specific user accounts, requests are also limited per email address. The `check_rate_limit` function uses the key `login:email:{normalized_email}` with limits from `settings.LOGIN_EMAIL_LIMIT` within the same `settings.RATE_LIMIT_WINDOW_SECONDS`.

### Global Rate Limit
A global rate limit is in place to protect the entire application from a high volume of requests. This uses the key `login:global` and limits defined by `settings.LOGIN_GLOBAL_LIMIT` within `settings.RATE_LIMIT_WINDOW_SECONDS`.