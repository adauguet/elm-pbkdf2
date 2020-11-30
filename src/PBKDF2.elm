module PBKDF2 exposing
    ( Error(..)
    , PRF
    , hmacSha1
    , pbkdf2
    )

import Bitwise
import Bytes exposing (Bytes, Endianness(..))
import Bytes.Decode as D
import Bytes.Encode as E
import HmacSha1
import HmacSha1.Key as Key


type alias PRF =
    Bytes -> Bytes -> Bytes


type Error
    = DerivedKeyTooLong
    | DecodingError


hmacSha1 : PRF
hmacSha1 password salt =
    let
        key =
            Key.fromBytes password
    in
    HmacSha1.fromBytes key salt |> HmacSha1.toBytes


pbkdf2 : ( PRF, Int ) -> Bytes -> Bytes -> Int -> Int -> Result Error Bytes
pbkdf2 ( prf, hLen ) p s c dkLen =
    if dkLen > (2 ^ 32 - 1) * hLen then
        Err DerivedKeyTooLong

    else
        let
            l =
                ceiling <| toFloat dkLen / toFloat hLen


            ts : List Bytes
            ts =
                List.map t (List.range 1 l)

            t : Int -> Bytes
            t i =
                let
                    u1 =
                        prf p
                            ([ E.bytes s, E.unsignedInt32 BE i ]
                                |> E.sequence
                                |> E.encode
                            )
                in
                case c of
                    1 ->
                        u1

                    _ ->
                        u 2 u1 u1

            u : Int -> Bytes -> Bytes -> Bytes
            u index previousU acc =
                let
                    nextU =
                        prf p previousU
                in
                if index == c then
                    xor acc nextU

                else
                    u (index + 1) nextU (xor acc nextU)
        in
        ts
            |> List.map E.bytes
            |> E.sequence
            |> E.encode
            |> D.decode (D.bytes dkLen)
            |> Result.fromMaybe DecodingError



-- helpers


xor : Bytes -> Bytes -> Bytes
xor a b =
    List.map2 Bitwise.xor (fromBytes a) (fromBytes b)
        |> toBytes


fromBytes : Bytes -> List Int
fromBytes bytes =
    let
        decoder_ accumulator width =
            if width == 0 then
                D.succeed (List.reverse accumulator)

            else
                D.unsignedInt8
                    |> D.andThen (\int -> decoder_ (int :: accumulator) (width - 1))
    in
    bytes
        |> D.decode (decoder_ [] (Bytes.width bytes))
        |> Maybe.withDefault []


toBytes : List Int -> Bytes
toBytes =
    E.encode << E.sequence << List.map E.unsignedInt8
