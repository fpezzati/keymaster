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

## 20240617
Refactoring and rewriting.. hyper ver 1+ is too f@*!ng complicate.

## 20240816
Ok, now I am getting a positive interaction while using github, but I cannot use google because he needs a different token request url...

I fear I have to split codebase, one function for idp.

## 20240923
Bubbling errors instead of returning http error responses. I have to get cookie lib to produce http only and secure cookies, both values are false despite the fact I put them to true.

## 20240929
Didn't turn http error responses into errors.. Unsure that helps. Now I want user email from IdP.

Ingress is ok, I have to integrate my auth proxy with nginx-ingress-controller. See [this](https://kubernetes.github.io/ingress-nginx/examples/auth/oauth-external-auth/).

## 20241008
Client part works but's ugly...Most important: it hasn't good error handling. The code I wrote risks to panic. I don't want that auth client panic because service must stay on if any of its clients fails.
I am stumbling into some pyramid of doom while handling Result, guess I am doing things weird.

So, I start removing code about returning axum's Response and return a Result with a custom error instead. Not sure that's good way to go, I am from java, error handling is an entire different thing there.
Using a custom error should give me confidence about what error my functions should return.

## 20241019
Improving error handling also means to remove unnecessary unwraps.. Code is a bit naive.

## 20241020
Giving `std::result::Result` a better look.

## 20241024
I introduce use of `map_err`. My may-fail functions always return `Result<whatever, GithubErr>`, a custom error.

Fetching github user's email fails, but I had no more panics and tokio continues to serve requests. That's good.

## 20241026
Now that I have normalized errors by `map_err` I can go after this new main issue: can't fetch user's email by github api.. Then I'll be back on code cleaning.

## 20241028
Github apis are ok, fetching user email by curl was cakewalk with given token. My request is wrong.

## 20241101
It was the `User-Agent` header that I was missing... That was totally uncovered into docs. Now it works.

## 20241102
Removing a couple of unwraps. I guess I have to use an enum instead of a single `GithubErr`. We'll see. Next thing is: integrate another IdP by loading code as separate module (webassembly?).

## 20241105
Errors handling can be better with enum, I guess I'll get rid of dummy duplications. I also have to implement the 'verify' function. Or should I move to next IdP?

## 20241109
Error handling is no better with enums to me. After a brief experiment I decide to turn back on structs, maybe I am OOP biased, but they make more sense to me than enums. Way more easy..

## 20241110
I was able to get better error handling and a full working authentication run.

## 20241118
I realize following things:
- cookie I build are naive,
- cookie building should not stay into idp file, the github.rs, but stay in server. What is in github.rs should only care about picking token and related username/email,
- cookie I build is NOT secure and NOT httponly. How's that possible?

## 20241127
I left this log behind. I implement the 'verify' function, I also decide it is time to move functions from github and verify mods; these mods should follow SRP so just respectively do provide token and validate a token.

Moving accessory functions outside the two mods and into server mod. The verify mod is already clean, let's go for github.

Changing opinion again about errors... Enums aren't cool..

## 20241130
Rearranged functions in module with proper responsibility.

Still struggling with error management.
