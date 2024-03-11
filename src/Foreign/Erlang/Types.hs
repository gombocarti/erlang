{-# OPTIONS -XFlexibleInstances -XTypeSynonymInstances #-}

-- |
-- Module      : Foreign.Erlang.OTP
-- Copyright   : (c) Eric Sessoms, 2008
--               (c) Artúr Poór, 2015
-- License     : GPL3
-- 
-- Maintainer  : gombocarti@gmail.com
-- Stability   : experimental
-- Portability : portable
--

module Foreign.Erlang.Types (
  -- * Native Erlang data types
    ErlType(..)
  -- ** Conversion between native Haskell types and ErlType
  , Erlang(..)
  -- ** Easy type-safe access to tuple members
  , nth

  -- ** Internal packing functions
  , getA, getC, getErl, getN, getM, geta, getn
  , putA, putC, putErl, putN, putM, puta, putn
  , tag
  ) where

import Prelude hiding (id)
import qualified Prelude  (id)
import Control.Exception  (assert)
import Control.Monad      (forM, liftM)
--import Data.Int (Int64)
import Data.Monoid        ((<>),mconcat)
import Data.Binary
import Data.Binary.Get
import Data.Char          (chr, ord, isPrint)
import qualified Data.ByteString.Lazy       as B
import qualified Data.ByteString.Lazy.Char8 as C
import qualified Data.ByteString.Char8      as BB
import Data.ByteString.Builder

import qualified Data.ByteString            as Byte
import Data.ByteString (ByteString)
import Control.Applicative
import Data.Bits(shiftL,complement,(.|.))


nth                  :: Erlang a => Int -> ErlType -> a
nth i (ErlTuple lst) = fromErlang $ lst !! i

data ErlType = ErlNull
             | ErlInt Int
             | ErlFloat  Double
             | ErlBigInt Integer
             | ErlString String
             | ErlAtom String
             | ErlBinary [Word8]
             | ErlList [ErlType]
             | ErlTuple [ErlType]
             | ErlPid ErlType Int Int Int     -- node id serial creation
             | ErlPort ErlType Int Int        -- node id creation
             | ErlRef ErlType Int Int         -- node id creation
             | ErlNewRef ErlType Int [Word8]  -- node creation id
             deriving (Eq, Show)

class Erlang a where
    toErlang   :: a -> ErlType
    fromErlang :: ErlType -> a

instance {-# OVERLAPPING #-} Erlang ErlType where
    toErlang   = Prelude.id
    fromErlang = Prelude.id

instance {-# OVERLAPPING #-} Erlang Int where
    toErlang   x
       | abs x <= 0x7FFFFFFF = ErlInt x
       | otherwise           = ErlBigInt (fromIntegral x) -- Haskell Int (might) use 64 bits whether erlang's small Int use only 32 bit

    fromErlang (ErlInt x)    = x
    fromErlang (ErlBigInt x) = fromIntegral x

instance {-# OVERLAPPING #-} Erlang Double where
    toErlang   x            = ErlFloat x
    fromErlang (ErlFloat x) = x

instance {-# OVERLAPPING #-} Erlang Float where
    toErlang x              = ErlFloat (realToFrac x)
    fromErlang (ErlFloat x) = realToFrac x

instance {-# OVERLAPPING #-} Erlang Integer where
    toErlang   x             = ErlBigInt x
    fromErlang (ErlInt x)    = fromIntegral x
    fromErlang (ErlBigInt x) = x

instance {-# OVERLAPPING #-} Erlang String where
    toErlang   x             = ErlString x
    fromErlang ErlNull       = ""
    fromErlang (ErlString x) = x
    fromErlang (ErlAtom x)   = x
    fromErlang (ErlList xs)  = map (chr . fromErlang) xs
    fromErlang x             = error $ "can't convert to string: " ++ show x

instance {-# OVERLAPPING #-} Erlang Bool where
    toErlang   True              = ErlAtom "true"
    toErlang   False             = ErlAtom "false"
    fromErlang (ErlAtom "true")  = True
    fromErlang (ErlAtom "false") = False

instance {-# OVERLAPPING #-} Erlang [ErlType] where
    toErlang   []           = ErlNull
    toErlang   xs           = ErlList xs
    fromErlang ErlNull      = []
    fromErlang (ErlList xs) = xs

instance {-# OVERLAPPING #-} Erlang a => Erlang [a] where
    toErlang   []           = ErlNull
    toErlang   xs           = ErlList . map toErlang $ xs
    fromErlang ErlNull      = []
    fromErlang (ErlList xs) = map fromErlang xs

instance {-# OVERLAPPING #-} (Erlang a, Erlang b) => Erlang (a, b) where
    toErlang   (x, y)            = ErlTuple [toErlang x, toErlang y]
    fromErlang (ErlTuple [x, y]) = (fromErlang x, fromErlang y)

instance {-# OVERLAPPING #-} (Erlang a, Erlang b, Erlang c) => Erlang (a, b, c) where
    toErlang   (x, y, z)            = ErlTuple [toErlang x, toErlang y, toErlang z]
    fromErlang (ErlTuple [x, y, z]) = (fromErlang x, fromErlang y, fromErlang z)

instance {-# OVERLAPPING #-} (Erlang a, Erlang b, Erlang c, Erlang d) => Erlang (a, b, c, d) where
    toErlang   (x, y, z, w)            = ErlTuple [toErlang x, toErlang y, toErlang z, toErlang w]
    fromErlang (ErlTuple [x, y, z, w]) = (fromErlang x, fromErlang y, fromErlang z, fromErlang w)

instance {-# OVERLAPPING #-} (Erlang a, Erlang b, Erlang c, Erlang d, Erlang e) => Erlang (a, b, c, d, e) where
    toErlang   (x, y, z, w, a)            = ErlTuple [toErlang x, toErlang y, toErlang z, toErlang w, toErlang a]
    fromErlang (ErlTuple [x, y, z, w, a]) = (fromErlang x, fromErlang y, fromErlang z, fromErlang w, fromErlang a)

instance Binary ErlType where
    put = undefined
    get = getErl

      
putErl :: ErlType -> Builder
putErl (ErlInt val)
    | 0 <= val && val < 256 = tag 'a' <> putC val
    | otherwise             = tag 'b' <> putN val

putErl (ErlFloat val)       = tag 'c' <> byteString  (BB.pack . take 31 $ show val ++ repeat '\NUL')
putErl (ErlAtom val)        = tag 'd' <> putn (length val) <> putA val
putErl (ErlTuple val)
    | len < 256             = tag 'h' <> putC len <> val'
    | otherwise             = tag 'i' <> putN len <> val'
    where val' = mconcat . map putErl $ val
          len  = length val
putErl ErlNull              = tag 'j'
putErl (ErlString val)      = tag 'k' <> putn (length val) <> putA val
putErl (ErlList val)        = tag 'l' <> putN (length val) <> val' <> putErl ErlNull
    where val' = mconcat . map putErl $ val  
putErl (ErlBinary val)      = tag 'm' <> putN (length val) <> (lazyByteString . B.pack) val

putErl (ErlBigInt x) 
       | len > 255      = tag 'o' <> putN len <> byteString val 
       | otherwise      = tag 'n' <> putC len <> byteString val 
   where
     val = integerToBytes x
     len = Byte.length val -1


putErl (ErlRef node id creation) =
    tag 'e' <>
    putErl node <>
    putN id <>
    putC creation
putErl (ErlPort node id creation) = tag 'f' <> putErl node <> putN id <> putC creation
putErl (ErlPid node id serial creation) = tag 'g' <> putErl node <> putN id <> putN serial <> putC creation
putErl (ErlNewRef node creation id) =
    tag 'r' <>
    putn (length id `div` 4) <>
    putErl node <>
    putC creation <>
    (lazyByteString . B.pack) id

getErl :: Get ErlType
getErl = do
    tag <- liftM chr getC
    case tag of

      'a' -> liftM ErlInt getC

      'b' -> do x <- getN
                
                let valFrom32  
                      | x > 0x7FFFFFFF = x .|. complement 0xFFFFFFFF  
                      | otherwise      = x

                return (ErlInt valFrom32)
      'c' -> do parsed  <- reads . BB.unpack <$> getByteString 31  
                case parsed of
                  [(x,remains)]
                    | all (=='\NUL') remains -> return $ ErlFloat x 
                  _                          -> fail $ "could not parse float representation: "++show parsed

      'd' -> getn >>= liftM ErlAtom . getA
      'e' -> do
        node <- getErl
        id <- getN
        creation <- getC
        return $ ErlRef node id creation
      'f' -> do
        node <- getErl
        id <- getN
        creation <- getC
        return $ ErlPort node id creation
      'g' -> do
        node <- getErl
        id <- getN
        serial <- getN
        creation <- getC
        return $ ErlPid node id serial creation
      'h' -> getC >>= \len -> liftM ErlTuple $ forM [1..len] (const getErl)
      'i' -> getN >>= \len -> liftM ErlTuple $ forM [1..len] (const getErl)
      'j' -> return ErlNull
      'k' -> do
         len <- getn
         list <- getA len
         case all isPrint list of
           True -> return $ ErlString list
           False -> return . ErlList $ map (ErlInt . ord) list
      'l' -> do
        len <- getN
        list <- liftM ErlList $ forM [1..len] (const getErl)
        null <- getErl
        assert (null == ErlNull) $ return list
      'm' -> getN >>= liftM ErlBinary . geta

      'n' -> do  len <- getC
                 raw <- getByteString (len+1)
                 ErlBigInt <$> bytesToInteger raw
      
      'o' -> do  len <- getN
                 raw <- getByteString (len+1)
                 ErlBigInt <$> bytesToInteger raw

      'r' -> do
        len <- getn
        node <- getErl
        creation <- getC
        id <- forM [1..4*len] (const getWord8)
        return $ ErlNewRef node creation id

      'v' -> getn >>= liftM ErlAtom . getA

      'w' -> getC >>= liftM ErlAtom . getA

      'X' -> do
        node <- getErl
        id <- getN
        serial <- getN
        creation <- getN
        return $ ErlPid node id serial creation

      'Z' -> do -- XXX ref
        error "FIXME ref"

      x -> fail $ "Unsupported serialization code: " ++ show (ord x)


bytesToInteger :: ByteString -> Get Integer
bytesToInteger bts = case Byte.unpack bts of
                      0 : bts' -> return $          foldr step 0 bts'
                      1 : bts' -> return . negate $ foldr step 0 bts'
                      x : _    -> fail $ "Unexpected sign byte: " ++ show x
                      _        -> fail $ "Unexpected end of input at function 'bytesToInteger'"
  where
    step next acc = shiftL acc 8 + fromIntegral next


integerToBytes :: Integer -> ByteString
integerToBytes int = Byte.pack 
                   . fmap (fromIntegral.snd) 
                   . takeWhile not_zero 
                   $ iterate ((`divMod`256).fst) (abs int,sigByte)
  
  where
    not_zero (a,b)    = a + b /= 0
    sigByte | int > 0   = 0
            | otherwise = 1



tag :: Char -> Builder             
tag = charUtf8

putC :: Integral a => a -> Builder
putC = word8 . fromIntegral

putn :: Integral a => a -> Builder
putn = word16BE . fromIntegral

putN :: Integral a => a -> Builder
putN = word32BE . fromIntegral

putM :: Integral a => a -> Builder
putM = word64BE . fromIntegral

puta :: [Word8] -> Builder
puta = lazyByteString . B.pack

putA :: String -> Builder       
putA = stringUtf8

getC :: Get Int
getC = liftM fromIntegral getWord8

getn :: Get Int
getn = liftM fromIntegral getWord16be

getN :: Get Int
getN = liftM fromIntegral getWord32be

getM :: Get Int
getM = liftM fromIntegral getWord64be

geta :: Int -> Get [Word8]
geta = liftM B.unpack . getLazyByteString . fromIntegral

getA :: Int -> Get String
getA = liftM C.unpack . getLazyByteString . fromIntegral
