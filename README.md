# pbkdf2
PBKDF2 implementation in Elm

## Motivation

To date, PBKDF2 is one of the recommended hashing algorithm to be used on client side. You need to provide a password and a salt.

## Implementation details

Implementation is described in the RFC 2898. https://www.ietf.org/rfc/rfc2898.txt.

The algorithm will return an error if the derived key is too long.

## Example

```elm
import Bytes.Encode as E
import Hex.Convert as Hex
import HmacSha1
import HmacSha1.Key as Key
import PBKDF2 exposing (pbkdf2)

hmacSha1 : Bytes -> Bytes -> List Int
hmacSha1 key message =
    HmacSha1.fromBytes (Key.fromBytes key) message
        |> HmacSha1.toByteValues

computeHash : String -> String -> String
computeHash password salt =
    let
        p =
            E.encode <| E.string password

        s =
            E.encode <| E.string salt
    in
    pbkdf2 (hmacSha1, 20) p s 4096 20
        |> Result.map Hex.toString
```

## Testing

This package is tested against the test vectors in RFC 6070 https://www.ietf.org/rfc/rfc6070.txt.