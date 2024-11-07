# Social Club

Social Club helps to connect, learn, and thrive with resources, events, and a supportive community to help you adapt in Germany.

## Contribution

The platform is under active development. Feel free to open issues/ submit PRs.

### Local development set-up

The application requires a PostgreSQL database server to function properly (for how to provide connection details, see below).

In `src/` create an `.env` file with the following keys:

- SECRET_KEY (django secret key)
- SENDGRID_API_KEY (we use sendgrid as our email service)
- DEFAULT_FROM_EMAIL (verified email address on sendgrid)
- DB_NAME (database name)
- DB_USER (database user)
- DB_PASSWORD (database user password)
- DB_HOST (database server)
- DB_PORT (database port)
- STATIC_ROOT (where static files are ought to be stored)
- HOSTNAMES (in production, set it to "localhost,127.0.0.1")
- DEBUG (True in production, False otherwise)

Hint: make sure that the directory for static files exists if you intent to collect static files.
