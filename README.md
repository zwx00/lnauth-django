# LnAuth Django

This is a reusable Django application providing Lightning Network url authentication functionality.

Currently only `login` and `register` actions are supported.

## Installation

You can install LnAuth-Django using pip:

```bash
pip install lnauth-django
```

Or, if you're using pipenv:

```bash
pipenv install lnauth-django
```

## Configuration

Once installed, add `'lnauth_django'` to your `INSTALLED_APPS` setting:

```python
INSTALLED_APPS = [
    ...
    'lnauth_django',
    ...
]
```

Then, include the URL configuration in your project's urls:

```python
from django.urls import include, path

urlpatterns = [
    ...
    path('lnauth_django/', include('lnauth_django.urls')),
    ...
]
```

### Settings

Here are the settings you can set in your `settings.py` to customize Django My App:

- `LNURL_AUTH_ROOT_DOMAIN`: This is used to specify the domain for your app. By default, it should be the domain where your Django project is hosted. Required.

- `LNURL_AUTH_K1_TIMEOUT`: This is used to specify the timeout of the `k1` challenge in seconds. By default, it is set to `60 * 60` seconds (1 hour).

- `LNURL_AUTH_REGISTER_CALLBACK` and `LNURL_AUTH_LOGIN_CALLBACK`: This is used to specify the import path of the callback function to be executed after user registration / login. Both are optional.

    ```python
    LNURL_AUTH_REGISTER_CALLBACK = 'myapp.users.ln_auth.register_callback'
    ```

- `LNURL_AUTH_BACKEND`: This is used to specify the authentication backend that the library should use for login. Only needed if you're using multiple authentication backends.

- `LNURL_AUTH_LOGIN_AFTER_REGISTER`: Specify whether to automatically log in the user after registration. Default is `True`.


## Usage

This app exposes two endpoints:

- `/ln-auth-get-url`: Generate a LNURL to be used for authentication. Takes a query parameter called `action` which can be set to `login` or `register`.

- `/ln-auth`: Which is called by the authenticating wallet. Takes all the parameters as specificed in the [LNURL Auth spec](https://github.com/lnurl/luds/blob/luds/04.md).

Both will reject authenticated requests.

Any kind of frontend is out of scope for this library, but the intended approach is to render the link returned by `/ln-auth-get-url` as a QR code and allow the user to use their preferred lightning wallet to log in.

## Contributing

Pull requests and feature requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## TODO

- More integration tests on django side
- Some sort of rate limiting
- Other actions, in particular `link` for linking to existing accounts
## License

[MIT](https://choosealicense.com/licenses/mit/)
