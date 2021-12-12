# Helsinki profiili integration

This module integrates user data in Helsinki profiili to Drupal. Required Tunnistamo openid authentication.

Userdata is queried from graphql endpoint in Tunnistamo. Userdata is saved for request in class. Nothing is saved locally.

## Environment

USERINFO_ENDPOINT -> endpoint uri to /userinfo graphql endpoint
