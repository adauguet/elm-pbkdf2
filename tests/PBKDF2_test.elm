module PBKDF2_test exposing (suite)

import Bytes exposing (Endianness(..))
import Bytes.Encode as E
import Expect
import Hex.Convert as Hex
import PBKDF2 exposing (hmacSha1, pbkdf2)
import String
import Test exposing (Test, describe, test)


suite : Test
suite =
    describe "pbkdf2"
        [ -- source: https://www.ietf.org/rfc/rfc6070.txt
          describe "RFC 6070"
            [ pbkdf2Test
                { title = "1"
                , input =
                    { password = "password"
                    , salt = "salt"
                    , c = 1
                    , dkLen = 20
                    }
                , output = "0c60c80f961f0e71f3a9b524af6012062fe037a6"
                }
            , pbkdf2Test
                { title = "2"
                , input =
                    { password = "password"
                    , salt = "salt"
                    , c = 2
                    , dkLen = 20
                    }
                , output = "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
                }
            , pbkdf2Test
                { title = "3"
                , input =
                    { password = "password"
                    , salt = "salt"
                    , c = 4096
                    , dkLen = 20
                    }
                , output = "4b007901b765489abead49d926f721d065a429c1"
                }

            -- WARNING: this test takes a lot of times to perform
            -- , pbkdf2Test
            --     { title = "4"
            --     , input =
            --         { password = "password"
            --         , salt = "salt"
            --         , c = 16777216
            --         , dkLen = 20
            --         }
            --     , output = "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"
            --     }
            , pbkdf2Test
                { title = "5"
                , input =
                    { password = "passwordPASSWORDpassword"
                    , salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt"
                    , c = 4096
                    , dkLen = 25
                    }
                , output = "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"
                }
            , pbkdf2Test
                { title = "6"
                , input =
                    { password = "pass\u{0000}word"
                    , salt = "sa\u{0000}lt"
                    , c = 4096
                    , dkLen = 16
                    }
                , output = "56fa6aa75548099dcc37d7f03425e0c3"
                }
            ]
        ]



-- helpers


type alias Vector =
    { title : String
    , input :
        { password : String
        , salt : String
        , c : Int
        , dkLen : Int
        }
    , output : String
    }


pbkdf2Test : Vector -> Test
pbkdf2Test { title, input, output } =
    test title <|
        \_ ->
            let
                p =
                    E.encode <| E.string input.password

                s =
                    E.encode <| E.string input.salt
            in
            Expect.equal
                (pbkdf2 ( hmacSha1, 20 ) p s input.c input.dkLen
                    |> Result.map Hex.toString
                    |> Result.map String.toLower
                )
                (Ok output)
