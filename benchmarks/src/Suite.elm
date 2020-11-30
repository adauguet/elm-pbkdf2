module Example exposing (suite)

import Array
import Benchmark exposing (..)
import Benchmark.Runner exposing (BenchmarkProgram, program)
import PBKDF2 exposing (hmacSha1, pbkdf2)
import Bytes.Encode as E


suite : Benchmark
suite =
    let
        p =
            E.encode <| E.string "password"

        s =
            E.encode <| E.string "salt"
    in
    describe "pbkdf2"
        [ benchmark "c = 1, dkLen = 20" <|
            \_ -> pbkdf2 ( hmacSha1, 20 ) p s 1 20
        , benchmark "c = 2, dkLen = 20" <|
            \_ -> pbkdf2 ( hmacSha1, 20 ) p s 2 20
        , benchmark "c = 4096, dkLen = 20" <|
            \_ -> pbkdf2 ( hmacSha1, 20 ) p s 4096 20
        ]



main : BenchmarkProgram
main =
    program suite