-- |
-- Module      : Foreign.Erlang.Network
-- Copyright   : (c) Eric Sessoms, 2008
--               (c) Artúr Poór, 2015
-- License     : GPL3
-- 
-- Maintainer  : gombocarti@gmail.com
-- Stability   : experimental
-- Portability : portable
--

module Foreign.Erlang.Network (
  -- * Low-level communication with the Erlang Port-Mapper Daemon
    epmdGetNames
  , epmdGetPort
  , epmdGetPortR4
  , EpmdPort(..)
  , getEpmdPort
  , ErlRecv
  , ErlSend
  -- ** Representation of Erlang nodes
  , Name
  , HostName
  , Node(..)
  , node
  , getNodeIp
  , nodeName
  , erlConnect
  , toNetwork
  , Challenge(..)
  ) where

import Control.Exception        (assert, bracketOnError)
import Control.Monad            (liftM)
import Data.Binary.Get
import Data.Bits                ((.|.))
import Data.Char                (chr, ord)
import Data.Hash.MD5            (md5i, Str(..))
import Data.List                (unfoldr)
import Data.Word
import Foreign.Erlang.Types
import Network.Socket
import qualified Network.BSD as BSD
import System.Directory         (getHomeDirectory)
import System.FilePath          ((</>))
import System.IO
import System.Random            (randomIO)
import qualified Data.ByteString.Lazy.Char8 as B
import Data.ByteString.Builder
import Data.Monoid ((<>),mempty)

-- erlangVersion :: Int
-- erlangVersion = 5

erlangProtocolVersion :: Int
erlangProtocolVersion = 131

passThrough :: Char
passThrough = 'p'

getUserCookie :: IO String
getUserCookie = do
    home <- getHomeDirectory
    withFile (home </> ".erlang.cookie") ReadMode $ \h -> do
      eof <- hIsEOF h
      if eof
        then return ""
        else hGetLine h

toNetwork :: Int -> Integer -> [Word8]
toNetwork b n = reverse . take b $ unfoldr toNetwork' n ++ repeat 0
  where
    toNetwork' 0 = Nothing
    toNetwork' n = let (b, a) = n `divMod` 256 in Just (fromIntegral a, b)

erlDigest                  :: String -> Word32 -> [Word8]
erlDigest cookie challenge = let
    n = fromIntegral . md5i . Str $ cookie ++ show challenge
    in toNetwork 16 n

packn, packN :: Builder -> Builder
packn msg = putn (B.length msg') <> msg
    where msg' = toLazyByteString msg
packN msg = putN (B.length msg') <> msg
    where msg' = toLazyByteString msg

sendMessage :: (Builder -> Builder) -> (Builder -> IO ()) -> Builder -> IO ()
sendMessage pack out = out . pack

recvMessage :: Int -> (Int -> IO B.ByteString) -> IO B.ByteString
recvMessage hdrlen inf = (liftM (unpack hdrlen) $ inf hdrlen) >>= inf
  where
    unpack 2 = runGet getn
    unpack 4 = runGet getN

type ErlSend = (Maybe ErlType, Maybe ErlType) -> IO ()
type ErlRecv = IO (Maybe ErlType, Maybe ErlType)
      
erlSend :: (Builder -> IO ()) -> ErlSend
erlSend send (Nothing, _)    = send . lazyByteString $ B.empty
erlSend send (Just ctl, msg) = send $
    tag passThrough <>
    putMsg ctl <>
    maybe mempty putMsg msg
  where
    putMsg msg = 
      putC erlangProtocolVersion <>
      putErl msg
      
erlRecv :: IO B.ByteString -> ErlRecv
erlRecv recv = do
    bytes <- recv
    return . flip runGet bytes $ do
      empty <- isEmpty
      if empty
        then return (Nothing, Nothing)
        else do
          pt <- getC
          assert (chr pt == passThrough) $ return ()
          ctl <- getMsg
          empty <- isEmpty
          if empty
            then return (Just ctl, Nothing)
            else case ctl of
                   ErlTuple (ErlInt n:_) | n `elem` [2, 6] -> do
                     msg <- getMsg
                     return (Just ctl, Just msg)
                   _ -> return (Just ctl, Nothing)
  where
    getMsg = do
      ver <- getC
      assert (ver == erlangProtocolVersion) $ getErl

-- | Name of an Erlang node.
type Name = String

-- | Representation of an Erlang node on the network.     
data Node 
    = Short Name         -- ^ Local Erlang node.
    | Long Name HostName -- ^ Remote Erlang node.
      deriving (Eq,Show)

instance Erlang Node where
    toErlang (Short name)   = ErlString name
    toErlang (Long name ip) = ErlString name
    fromErlang = undefined

node :: String -> Node
node spec = let (name, _:host) = break (== '@') spec in Long name host

getNodeIp :: Node -> IO String
getNodeIp (Short name) = return epmdLocal
getNodeIp (Long name host) = resolve host

nodeName :: Node -> String
nodeName (Short name) = name
nodeName (Long name host) = name

erlConnect :: String -> Node -> IO (ErlSend, ErlRecv)
erlConnect self node = withSocketsDo $ do
  ip <- getNodeIp node
  port <- getEpmdPort node
  let port' = PortNumber . fromIntegral . epmdNodePort $ port
  withNode ip port' $ \h -> do
    let out = sendMessage packn (hPutBuilder h)
    let inf = recvMessage 2 (B.hGet h)
    challenge <- handshake out inf self
    let out' = sendMessage packN (hPutBuilder h)
    let inf' = recvMessage 4 (B.hGet h)
    return (erlSend out', erlRecv inf')

data Challenge = Challenge {
                  challengeFlags        :: Int,
                  challengeSalt         :: Word32,
                  challengeThisCreation :: Int,
                  challengeThatCreation :: Int
                } deriving (Show, Eq)

handshake :: (Builder -> IO ()) -> IO B.ByteString -> String -> IO Challenge
handshake out inf self = do
    cookie <- getUserCookie
    sendName
    recvStatus
    challenge <- recvChallenge
    let reply = erlDigest cookie $ challengeSalt challenge
    challenge' <- liftM fromIntegral (randomIO :: IO Int)
    challengeReply reply challenge'
    recvChallengeAck cookie challenge'
    return challenge

  where
    flagPublished          =  0x01
    flagAtomCache          =  0x02
    flagExtendedReferences =  0x04
    flagDistMonitor        =  0x08
    flagFunTags            =  0x10
    flagDistMonitorName    =  0x20
    flagHiddenAtomCache    =  0x40
    flagNewFunTags         =  0x80
    flagExtendedPidsPorts  = 0x100
    flagExportPtrTag       = 0x200
    flagBitBinaries        = 0x400
    flagNewFloats          = 0x800
    flagUnicodeIO          = 0x1000
    flagDistHdrAtomCache   = 0x2000
    flagUTF8Atoms          = 0x10000
    flagMapTag             = 0x20000
    flagBigCreation        = 0x40000

    flagHANDSHAKE_23      :: Word32
    flagHANDSHAKE_23       = 0x1000000

    flags' = 0x0000000d07df7fbd; -- Erlang/OTP 25 [erts-13.2.2.4]
    -- .... .... .... .... .... .... .... .... .... = Spare: 0
    -- 1... .... .... .... .... .... .... .... .... = Alias: True
    -- .1.. .... .... .... .... .... .... .... .... = V4 NC: True
    -- ..0. .... .... .... .... .... .... .... .... = Name ME: False
    -- ...1 .... .... .... .... .... .... .... .... = Spawn: True
    -- .... 0000 01.. .... .... .... .... .... .... = Reserved: 1
    -- .... .... ..1. .... .... .... .... .... .... = Unlink Id: True
    -- .... .... ...1 .... .... .... .... .... .... = Handshake 23: True
    -- .... .... .... 1... .... .... .... .... .... = Fragments: True
    -- .... .... .... .1.. .... .... .... .... .... = Exit Payload: True
    -- .... .... .... ..0. .... .... .... .... .... = Pending Connect: False
    -- .... .... .... ...1 .... .... .... .... .... = Big Seqtrace Labels: True
    -- .... .... .... .... 1... .... .... .... .... = Send Sender: True
    -- .... .... .... .... .1.. .... .... .... .... = Big Creation: True
    -- .... .... .... .... ..1. .... .... .... .... = Map Tag: True
    -- .... .... .... .... ...1 .... .... .... .... = UTF8 Atoms: True
    -- .... .... .... .... .... 0... .... .... .... = ETS Compressed: False
    -- .... .... .... .... .... .1.. .... .... .... = Small Atom Tags: True
    -- .... .... .... .... .... ..1. .... .... .... = Dist HDR Atom Cache: True
    -- .... .... .... .... .... ...1 .... .... .... = Unicode IO: True
    -- .... .... .... .... .... .... 1... .... .... = New Floats: True
    -- .... .... .... .... .... .... .1.. .... .... = Bit Binaries: True
    -- .... .... .... .... .... .... ..1. .... .... = Export PTR Tag: True
    -- .... .... .... .... .... .... ...1 .... .... = Extended Pids Ports: True
    -- .... .... .... .... .... .... .... 1... .... = New Fun Tags: True
    -- .... .... .... .... .... .... .... .0.. .... = Hidden Atom Cache: False
    -- .... .... .... .... .... .... .... ..1. .... = Dist Monitor Name: True
    -- .... .... .... .... .... .... .... ...1 .... = Fun Tags: True
    -- .... .... .... .... .... .... .... .... 1... = Dist Monitor: True
    -- .... .... .... .... .... .... .... .... .1.. = Extended References: True
    -- .... .... .... .... .... .... .... .... ..0. = Atom Cache: False
    -- .... .... .... .... .... .... .... .... ...1 = Published: True
    flags = flagHANDSHAKE_23
          .|. flagExtendedReferences
          .|. flagExtendedPidsPorts
          .|. flagUTF8Atoms
          .|. flagNewFunTags
          .|. flagBigCreation
          .|. flagMapTag
          .|. flagNewFloats
          .|. flagBitBinaries
          .|. flagExportPtrTag
          .|. flagFunTags
          .|. flagUnicodeIO
          -- .|. flagDistHdrAtomCache -- XXX need DistributionHeader
          -- .|. flagPublished

    creation = 0x3700037 -- FIXME ¿¿¿

    sendName = out $
        tag 'N' <>
        putM flags <>
        putN creation <>
        putn (length self) <>
        putA self

    recvStatus = fmap B.unpack inf >>= \msg ->
        case msg of
          "sok" -> return ()
          -- "ok_simultaneous" -> return () -- XXX enable with flagPublished
          "snot_allowed" -> error "handshake: they say we're not allowed"
          "salive" -> out $ putA "strue" -- restart
          status -> error $ "handshake: failed, status: " ++ status

    recvChallenge = do
        msg <- inf
        return . flip runGet msg $ getC >>= \tag ->
          if tag /= ord 'N'
            then error $ "handshake: incompatible protocol: " ++ show tag
            else do
              flags <- getM
              challenge <- getWord32be
              creation' <- getN
              return $ Challenge flags challenge creation creation'

    challengeReply reply challenge = out $
        tag 'r' <>
        word32BE challenge <>
        puta reply

    recvChallengeAck cookie challenge = do
        let digest = erlDigest cookie challenge
        msg <- inf
        let reply = take 16 . tail . map (fromIntegral . ord) . B.unpack $ msg
        if digest == reply
          then return ()
          else error "handshake: digest mismath"

epmdLocal :: HostName
epmdLocal = "127.0.0.1"
            
epmdPort :: PortID
--epmdPort = Service "epmd"
epmdPort = PortNumber 4369

withNode :: String -> PortID -> (Handle -> IO a) -> IO a
withNode epmd port = withSocketsDo . bracketOnError
    (connectTo epmd port)
    hClose

withEpmd :: String -> (Handle -> IO a) -> IO a
withEpmd epmd = withSocketsDo . bracketOnError
    (connectTo epmd epmdPort)
    hClose

epmdSend     :: String -> String -> IO B.ByteString
epmdSend epmd msg = withEpmd epmd $ \hdl -> do
    let out = putn (length msg) <> putA msg
    hPutBuilder hdl out
    hFlush hdl
    B.hGetContents hdl

-- | Return the names and addresses of registered local Erlang nodes.
epmdGetNames :: IO [String]
epmdGetNames = do
    reply <- epmdSend epmdLocal "n"
    let txt = runGet (getN >> liftM B.unpack getRemainingLazyByteString) reply
    return . lines $ txt

-- | Return the port address of a named Erlang node.
epmdGetPort      :: Node -> IO Int
epmdGetPort node = do
  reply <- epmdSend epmd $ 'z' : nodeName
  return $ flip runGet reply $ do
                     _ <- getC
                     res <- getC
                     if res == 0
                       then getn
                       else error $ "epmdGetPort: node not found: " ++ show node
    where (nodeName, epmd) = case node of
                           Short name    -> (name, epmdLocal)
                           Long  name ip -> (name, ip)

-- | Returns (port, nodeType, protocol, vsnMax, vsnMin, name, extra)
epmdGetPortR4 :: String -> String -> IO (Int, Int, Int, Int, Int, String, String)
epmdGetPortR4 epmd name = do
    reply <- epmdSend epmd $ 'z' : name
    return $ flip runGet reply $ do
        _ <- getn
        port <- getn
        nodeType <- getC
        protocol <- getC
        vsnMax <- getn
        vsnMin <- getn
        name <- getn >>= getA
        extra <- liftM B.unpack getRemainingLazyByteString
        return (port, nodeType, protocol, vsnMax, vsnMin, name, extra)

data EpmdPort = EpmdPort {
                  epmdNodePort  :: Int,
                  epmdNodeType  :: Int,
                  epmdProtocol  :: Int,
                  epmdVsnMax    :: Int,
                  epmdVsnMin    :: Int,
                  epmdNodeName  :: String,
                  epmdExtra     :: String
                } deriving (Show, Eq)

getEpmdPort :: Node -> IO EpmdPort
getEpmdPort node = do
  ip <- getNodeIp node
  reply <- epmdSend ip $ 'z' : nodeName node
  return $ flip runGet reply $ do
    tag <- getC
    if tag /= ord 'w'
      then error $ "getEpmdPort: unexpected tag: " ++ show tag
      else getC >>= \result ->
        case result of
          err | err > 1 -> error $ "getEpmdPort: failed: " ++ show err
          1 -> error $ "getEpmdPort: node not found: " ++ show node
          0 -> do
            port <- getn
            nodeType <- getC
            protocol <- getC
            vsnMax <- getn
            vsnMin <- getn
            name <- getn >>= getA
            extra <- liftM B.unpack getRemainingLazyByteString
            return $ EpmdPort port nodeType protocol vsnMax vsnMin name extra

-- setEpmdPort :: EpmdPort -> IO ()

-- XXX compat
data PortID = PortNumber PortNumber
connectTo :: HostName         -- Hostname
          -> PortID             -- Port Identifier
          -> IO Handle          -- Connected Socket
connectTo hostname (PortNumber port) = do
    proto <- BSD.getProtocolNumber "tcp"
    bracketOnError
        (socket AF_INET Stream proto)
        (close)  -- only done if there's an error
        (\sock -> do
          he <- BSD.getHostByName hostname
          connect sock (SockAddrInet port (BSD.hostAddress he))
          socketToHandle sock ReadWriteMode
        )

inet_addr :: HostName -> IO HostAddress
inet_addr hostname = do
  let hints = defaultHints { addrFlags = [AI_NUMERICHOST], addrSocketType = Stream }
  addr:_ <- getAddrInfo (Just hints) (Just hostname) Nothing
  let SockAddrInet _ address = addrAddress addr
  return address

resolve :: String -> IO String -- TODO IPv6
resolve = liftM hostEntryToString . BSD.getHostByName where
  hostEntryToString = tupleToString . hostAddressToTuple . BSD.hostAddress
  tupleToString (a,b,c,d) = foldr tupleFold "" [d,c,b,a]
  tupleFold v "" = show v
  tupleFold v a = a ++ "." ++ show v
