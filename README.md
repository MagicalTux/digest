# digest
Simple HTTP digest lib in Go (yes, yet another one blah blah)

# usage

After importing the digest lib:

```go
  headers.Set("WWW-Authenticate", MakeDigestHeader(AuthDigest("realm")))
```

And to check the result:

```go
  auth := p.Headers.Get("Authorization")
  if len(auth) > 7 && auth[0:7] == "Digest " {
    info, err := digest.CheckDigestResponse(digest.ParsePairs(auth[7:]))
    // check err
    // check info.Username
    err = info.CheckPassword("GET", "good password")
    // check err again
    ...
```
