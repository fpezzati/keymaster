# Keymaster
Provides:
- jwt validation utility,
- jwt token creation,
- jwt token blacklisting (?).

Built in rust with:
- [axum](https://github.com/tokio-rs/axum) ver 0.5.16.
- [jwt-simple](https://docs.rs/jwt-simple/latest/jwt_simple/) ver 0.10

## 20221111
Right now keymaster provides jwt validation utility and jwt token creation. Jwt validation is straightforward, but what about token creation? Just now keymaster provides a new token, no check if provided username and password match agains anything.

Well, keymaster should match user's credentials agains a database, question is: what keymaster should provide? Let's think about some scenarios.

### Scenario 1
Should provide an http endpoint for user creation which returns an UUID identifier, another application provides user creation web interface and user profile managemnet:
- when user wants to login, he lands on a web page which calls keymaster and gets a token. Web page belongs to application that provides CRUD about user profile, let's call it user application,
- when user wants to register, he lands on user application proper page. User application invokes keymaster creation endpoint and grab the uuid keymaster provides to create a user profile. User credentials and user profile are bound by that uuid.
Big win: this is exactly what I need to go further, no need for user profile right now. Big loss: user creation implies two apps to synchronize.

### Scenario 2
keymaster provides everything. She handles both user credentials and user profile, it becomes a normal front-end back-end app.
Big win: user registration involves only one app. Big loss: putting a lot of stuff early, difficult to integrate. Maybe no big loss..

### Scenario 3
Integrate this with some OAuth or OAuth2 provider.

## 20230122
Raise from the death! Keymaster returns to handle login. Cannot get how to achieve login with nginx (how to put oauth2 token into a httponly secure cookie?). Moreover: I want to share my jwt token! This way I can validate my token instead of asking someone else to do that. Maybe instead of having another pod, gatekeeper and keymaster may be two containers sharing the same pod... Who knows.

## 20230123
Scenario 3 tooks hold on keymaster. Service will provide an endpoint to get a token and an endpoint to verify that.

## 20230902
Let's drop some instructions.

### Sample config
configuration is expected into `./conf.json` file, otherwise you can override that with `--config_file /path/to/your/config/file`.

Configuration has the form of:
```
{
    host: "host",
    port: "port",
    public_key: "some public key",
    private_key: "some private key",
    github_oauth2: {
      client_id: "your client id",
      redirect_uri: "redirect_uri",
      client_secret: "client_secret",
      idp_url: "provider you will call for"
    }
}
```
Then do an http GET call like this:
```
https://github.com/login/oauth/authorize?clientid=your_client_id&redirect_uri=your_redirect_uri&scope=user
```

## 20230917
I loose more code than I thought.. I have to rebuild the function that checks token too. Today I'll try to pass server as state to handlers.

## 20240526
It has been a long time. Some considerations:
- no need of specialized handlers, auth2 is the same for every authentication providers, what really changes is configuration,
- figure out multithread vs async for requests, maybe async is not feasible,
- figure out a way that tells which authentication provider is being used.

Moreover, my code organization is a bit naive.. Configuration will stay the same.

Well, keymaster appears to be broken.. `Unable to find libclang: "couldn't find any valid shared libraries matching...` what's that?