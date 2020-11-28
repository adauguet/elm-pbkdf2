module HmacSha1_test exposing (suite)

import Bytes exposing (Bytes)
import Bytes.Encode as E
import Expect
import Hex.Convert as Hex
import HmacSha1
import HmacSha1.Key
import String
import String.Extra as String
import Test exposing (Test, describe, test)


suite : Test
suite =
    describe "hmac-sha-1"
        [ -- source: https://tools.ietf.org/html/rfc2202
          describe "RFC 2202"
            [ hmacSha1Test
                { testCase = 1
                , key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" |> hexStringToBytes |> HmacSha1.Key.fromBytes
                , data = "Hi There" |> E.encode << E.string
                , digest = "b617318655057264e28bc0b6fb378c8ef146be00"
                }
            , hmacSha1Test
                { testCase = 2
                , key = "Jefe" |> HmacSha1.Key.fromString
                , data = "what do ya want for nothing?" |> E.encode << E.string
                , digest = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
                }
            , hmacSha1Test
                { testCase = 3
                , key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" |> hexStringToBytes |> HmacSha1.Key.fromBytes
                , data = String.repeat 50 "dd" |> hexStringToBytes
                , digest = "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
                }
            , hmacSha1Test
                { testCase = 4
                , key = "0102030405060708090a0b0c0d0e0f10111213141516171819" |> hexStringToBytes |> HmacSha1.Key.fromBytes
                , data = String.repeat 50 "cd" |> hexStringToBytes
                , digest = "4c9007f4026250c6bc8414f9bf50c86c2d7235da"
                }
            , hmacSha1Test
                { testCase = 5
                , key = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c" |> hexStringToBytes |> HmacSha1.Key.fromBytes
                , data = "Test With Truncation" |> E.encode << E.string
                , digest = "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"
                }
            , hmacSha1Test
                { testCase = 6
                , key = String.repeat 80 "aa" |> hexStringToBytes |> HmacSha1.Key.fromBytes
                , data = "Test Using Larger Than Block-Size Key - Hash Key First" |> E.encode << E.string
                , digest = "aa4ae5e15272d00e95705637ce8a3b55ed402112"
                }
            , hmacSha1Test
                { testCase = 7
                , key = String.repeat 80 "aa" |> hexStringToBytes |> HmacSha1.Key.fromBytes
                , data = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data" |> E.encode << E.string
                , digest = "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
                }
            ]
        ]



-- helpers


hexStringToBytes : String -> Bytes
hexStringToBytes string =
    case Hex.toBytes string of
        Just bytes ->
            bytes

        Nothing ->
            hexStringToBytes string


hmacSha1Test : HmacSha1TestCase -> Test
hmacSha1Test { testCase, key, data, digest } =
    test ("hmac-sha-1 - " ++ String.fromInt testCase) <|
        \_ ->
            Expect.equal (HmacSha1.fromBytes key data |> HmacSha1.toHex) digest


type alias HmacSha1TestCase =
    { testCase : Int
    , key : HmacSha1.Key.Key
    , data : Bytes
    , digest : String
    }
