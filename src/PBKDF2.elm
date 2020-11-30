module PBKDF2 exposing
    ( pbkdf2
    , Error(..)
    )

{-|


# Computing pbkdf2 digest

@docs pbkdf2

@docs Error

-}

import Bitwise
import Bytes exposing (Bytes, Endianness(..))
import Bytes.Decode as D
import Bytes.Encode as E


{-| The error than can be returned
-}
type Error
    = DerivedKeyTooLong
    | DecodingError


{-| Computes the pbkdf2 digest
-}
pbkdf2 : ( Bytes -> Bytes -> Bytes, Int ) -> Bytes -> Bytes -> Int -> Int -> Result Error Bytes
pbkdf2 ( prf, hLen ) password salt c dkLen =
    if dkLen > (2 ^ 32 - 1) * hLen then
        Err DerivedKeyTooLong

    else
        let
            l : Int
            l =
                ceiling <| toFloat dkLen / toFloat hLen

            ts : List (List Int)
            ts =
                List.map t (List.range 1 l)

            t : Int -> List Int
            t i =
                let
                    u1 =
                        prf password
                            ([ E.bytes salt, E.unsignedInt32 BE i ]
                                |> E.sequence
                                |> E.encode
                            )
                            |> bytesToInts
                in
                case c of
                    1 ->
                        u1

                    _ ->
                        u 2 u1 u1

            u : Int -> List Int -> List Int -> List Int
            u index previousU acc =
                let
                    nextU =
                        (prf password <| intsToBytes previousU) |> bytesToInts
                in
                if index == c then
                    xor acc nextU

                else
                    u (index + 1) nextU (xor acc nextU)
        in
        ts
            |> List.concat
            |> intsToBytes
            |> D.decode (D.bytes dkLen)
            |> Result.fromMaybe DecodingError



-- helpers, not exposed


xor : List Int -> List Int -> List Int
xor a b =
    List.map2 Bitwise.xor a b


intsToBytes : List Int -> Bytes
intsToBytes =
    E.encode << E.sequence << List.map E.unsignedInt8



-- source: https://github.com/romariolopezc/elm-hmac-sha1 internals


bytesToInts : Bytes -> List Int
bytesToInts bytes =
    let
        decoder accumulator width =
            if width == 0 then
                D.succeed (List.reverse accumulator)

            else
                D.unsignedInt8
                    |> D.andThen (\int -> decoder (int :: accumulator) (width - 1))
    in
    bytes
        |> D.decode (decoder [] (Bytes.width bytes))
        |> Maybe.withDefault []
