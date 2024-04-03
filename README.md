# neo4j-sso-keycloak
Example project for configuring Neo4j with Keycloak

- Clone `git@github.com:StephenCathcart/neo4j-sso-keycloak.git`
- Run `./generate-certificates.sh` from the root of the project, it will generate the necessary certificates.
- Run `docker-compose -f docker-compose.yml up -d --remove-orphans` from the root of the project.

This will start up 5 containers - Neo4j, Keycloak, and Postgres (used as a repository for Keycloak), and two config containers.

After about a minute the config containers will be destroyed and we're good to go, run docker ps to check you have the following containers:
- `sso-keycloak_keycloak_1`
- `sso-keycloak_postgres_1`
- `sso-keycloak_neo4j_1`

- Confirm the database is configured correctly by navigating to http://localhost:7687/ and check that Keycloak exists as an oidc_provider.

- Confirm SSO is working by navigating to browser (http://localhost:7474/browser/), and select Authentication type -> Single Sign On. You should see a Keycloak button. Press it to be redirected to Keycloak and sign in (use username: `admin`, password: `password`).

- You should now be connected in Browser as `dave.lister@example.com`.

- You can manually sign-in to Keycloaks' admin console here: http://127.0.0.1:8180/. This is sometimes useful to logout of sessions or configure token expiration times.

- By default it's setup for Access Tokens to expire after 5 minutes and Refresh Tokens to expire after 30 minutes.

- Use your language of choice SSO client library to request a JWT from Keycloak and use this as the driver credentials (for Golang I used https://github.com/Nerzal/gocloak).

### Go example:
```
fetchAuthTokenFromMyProvider := func(ctx context.Context) (neo4j.AuthToken, *time.Time, error) {
    // Get our JWT from provider.
    jwt, _ := getJWT(ctx)
    // Set expiration from JWT.
    expiresIn := time.Now().Add(time.Duration(jwt.ExpiresIn) * time.Second)
	// Include a little buffer so that we fetch a new token *before* the old one expires.
	expiresIn = expiresIn.Add(-10 * time.Second)
    return neo4j.BearerAuth(jwt.AccessToken), nil, nil
}
...
neo4j.NewDriverWithContext("neo4j://localhost:7687", auth.BearerTokenManager(fetchAuthTokenFromMyProvider)
...
func getJWT(ctx context.Context) (*gocloak.JWT, error) {
	client := gocloak.NewClient("http://127.0.0.1:8180")
    // If initial log in
	return client.Login(ctx, "neo4j-sso", "", "my-realm", "admin", "password")
    ...
    // If refreshing
    return client.RefreshToken(ctx, originalToken.RefreshToken, "neo4j-sso", "", "my-realm")
}
```

Example application / BOLT logs for when the refresh happens:

```
2023-10-04 13:33:58.697  DEBUG  [session 22] Retrying transaction (): TokenExpiredError: Neo.ClientError.Security.TokenExpired (Authorization info expired.) [after 1.936834574s]
2023-10-04 13:34:00.634  DEBUG  [session 22] connection acquisition timeout is 1m0s, resolved deadline is: 2023-10-04 13:35:00.634353 +0100 BST m=+157.128034490
2023-10-04 13:34:00.634  DEBUG  [pool 1] Trying to borrow connection from [localhost:7687]
2023-10-04T13:34:00+01:00 Refreshing JWT
2023-10-04 13:34:00.646   INFO  [bolt4 bolt-518@localhost:7687] Closing connection because auth token expired (informed by auth manager)
2023-10-04 13:34:00.646   INFO  [bolt4 bolt-518@localhost:7687] Close
2023-10-04 13:34:00.646   BOLT  [bolt-518@localhost:7687] C: GOODBYE
2023-10-04 13:34:00.646   INFO  [pool 1] Connecting to localhost:7687
2023-10-04 13:34:00.646   INFO  [bolt4 bolt-518@localhost:7687] Close
2023-10-04 13:34:00.646   WARN  [driver localhost:7687] could not close underlying socket
2023-10-04 13:34:00.646   BOLT  C: <MAGIC> 0X6060B017
2023-10-04 13:34:00.646   BOLT  C: <HANDSHAKE> 0X00030305 0X00020404 0X00000104 0X00000003
2023-10-04 13:34:00.648   BOLT  S: <HANDSHAKE> 0X00000404
2023-10-04 13:34:00.648   BOLT  C: HELLO {"credentials":"<redacted>","patch_bolt":["utc"],"routing":{"address":"localhost:7687"},"scheme":"bearer","user_agent":"Go Driver/5.12.0"}
2023-10-04 13:34:00.650   BOLT  S: SUCCESS {"server":"Neo4j/4.4.9","connection_id":"bolt-519"}
2023-10-04 13:34:00.650   INFO  [bolt4 bolt-519@localhost:7687] Connected
```
