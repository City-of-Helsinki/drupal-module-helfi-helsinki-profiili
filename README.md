# Helsinki profiili integration

This module integrates user data in Helsinki profiili to Drupal. Required Tunnistamo openid authentication.

Userdata is queried from graphql endpoint in Tunnistamo. Userdata is saved for request in class. Nothing is saved locally.

## Configuration

```
  - roles:
  hp_user_roles:
    - 'helsinkiprofiili'
  admin_user_roles: []
  - clients:
    hp_user_client: 'tunnistamo'
    hp_admin_client: 'tunnistamoadmin'

```

## Environment

USERINFO_ENDPOINT -> endpoint uri to /userinfo graphql endpoint


TUNNISTAMO_API_TOKEN_ENDPOINT -> endpoint uri to /api-tokens endpoint

## Tests

This module has unit tests. You need to have this module inside a working drupal installation.

Command to run the tests: ```vendor/bin/phpunit public/modules/contrib/helfi_helsinki_profiili```
