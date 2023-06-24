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

## Usage

This section describes how to use the main functionalities provided by LnAuth Django...

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](https://choosealicense.com/licenses/mit/)
